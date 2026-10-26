package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ir-toolkit/internal/packageio"
)

// Heavy synthetic profiling is opt-in and test-only. Each operation gets a fresh
// process so retained Go caches from an earlier operation do not mask its cost.
type packageResourceResult struct {
	Scenario      string `json:"scenario"`
	Operation     string `json:"operation"`
	GoOS          string `json:"goos"`
	GoArch        string `json:"goarch"`
	GoVersion     string `json:"go_version"`
	GOGCEnv       string `json:"gogc_env"`
	GOMEMLIMITEnv string `json:"gomemlimit_env"`
	DiskMode      string `json:"disk_mode"`
	FileCount     int    `json:"file_count"`
	PayloadBytes  int64  `json:"payload_bytes"`
	DomainRecords int    `json:"domain_records"`
	DurationMS    int64  `json:"duration_ms"`
	BaselineHeap  uint64 `json:"baseline_heap_bytes"`
	PeakHeap      uint64 `json:"sampled_peak_heap_bytes"`
	PeakGoSys     uint64 `json:"sampled_peak_go_sys_bytes"`
	Allocated     uint64 `json:"total_alloc_delta_bytes"`
	DiskBefore    int64  `json:"workspace_before_bytes"`
	PeakDisk      int64  `json:"sampled_peak_workspace_bytes"`
	DiskAfter     int64  `json:"workspace_after_bytes"`
}

type resourceSampler struct {
	mu                sync.Mutex
	peakHeap, peakSys uint64
	peakDisk          int64
	err               error
}

func logicalWorkspaceBytes(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		// Normal extraction/stage cleanup can race a sampled walk.
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected non-regular measurement file %q", path)
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func (s *resourceSampler) heap() {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	s.mu.Lock()
	defer s.mu.Unlock()
	if stats.HeapAlloc > s.peakHeap {
		s.peakHeap = stats.HeapAlloc
	}
	if stats.Sys > s.peakSys {
		s.peakSys = stats.Sys
	}
}

func (s *resourceSampler) disk(root string) {
	count, err := logicalWorkspaceBytes(root)
	s.mu.Lock()
	defer s.mu.Unlock()
	if count > s.peakDisk {
		s.peakDisk = count
	}
	if err != nil && s.err == nil {
		s.err = err
	}
}

func TestPackageResourceWorker(t *testing.T) {
	if os.Getenv("IR_PACKAGE_RESOURCE_WORKER") != "1" {
		t.Skip("resource subprocess helper")
	}
	root := os.Getenv("IR_PACKAGE_RESOURCE_ROOT")
	operation := os.Getenv("IR_PACKAGE_RESOURCE_OPERATION")
	diskMode := os.Getenv("IR_PACKAGE_RESOURCE_DISK_MODE")
	if diskMode == "" {
		diskMode = "sampled"
	}
	if diskMode != "sampled" && diskMode != "checkpoints" {
		t.Fatalf("invalid disk measurement mode %q", diskMode)
	}
	source, packet := filepath.Join(root, "source"), filepath.Join(root, "case.tar")
	parent, repository := filepath.Join(root, "temporary"), filepath.Join(root, "repository")
	runtime.GC()
	var baseline runtime.MemStats
	runtime.ReadMemStats(&baseline)
	diskBefore, err := logicalWorkspaceBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	sampler := &resourceSampler{peakHeap: baseline.HeapAlloc, peakSys: baseline.Sys, peakDisk: diskBefore}
	done := make(chan struct{})
	var workers sync.WaitGroup
	for _, kind := range []string{"heap", "disk"} {
		if kind == "disk" && diskMode == "checkpoints" {
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			interval := 10 * time.Millisecond
			if kind == "disk" {
				interval = 100 * time.Millisecond
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					if kind == "heap" {
						sampler.heap()
					} else {
						sampler.disk(root)
					}
				}
			}
		}()
	}
	checkpoint := func(string) { sampler.heap(); sampler.disk(root) }
	started := time.Now()
	var verified packageio.ContainerVerification
	switch operation {
	case "export":
		verified, err = packCaseFile(context.Background(), source, packet)
	case "verify":
		verified, err = verifyCaseFile(context.Background(), packet)
	case "extract":
		file, openErr := os.Open(packet)
		if openErr != nil {
			err = openErr
			break
		}
		extracted, extractErr := packageio.Extract(context.Background(), file, parent, packageio.DefaultLimits())
		closeErr := file.Close()
		if extractErr != nil {
			err = extractErr
			break
		}
		verified = extracted.Verification
		checkpoint("extracted")
		err = extracted.Close()
		if err == nil {
			err = closeErr
		}
	case "import":
		_, err = importPackageFileWithHooks(context.Background(), packet, repository, "resource-case", parent, packageImportHooks{checkpoint: checkpoint})
	default:
		err = fmt.Errorf("unknown measurement operation %q", operation)
	}
	checkpoint("finished")
	close(done)
	workers.Wait()
	duration := time.Since(started)
	var final runtime.MemStats
	runtime.ReadMemStats(&final)
	if err != nil {
		t.Fatal(err)
	}
	if sampler.err != nil {
		t.Fatal(sampler.err)
	}
	if operation == "import" {
		verified, err = verifyCaseFile(context.Background(), packet)
		if err != nil {
			t.Fatal(err)
		}
	}
	diskAfter, err := logicalWorkspaceBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	result := packageResourceResult{Scenario: os.Getenv("IR_PACKAGE_RESOURCE_SCENARIO"), Operation: operation, GoOS: runtime.GOOS, GoArch: runtime.GOARCH, GoVersion: runtime.Version(),
		GOGCEnv: os.Getenv("GOGC"), GOMEMLIMITEnv: os.Getenv("GOMEMLIMIT"), DiskMode: diskMode,
		FileCount: len(verified.Metadata.Files), PayloadBytes: verified.PayloadBytes, DurationMS: duration.Milliseconds(), BaselineHeap: baseline.HeapAlloc,
		PeakHeap: sampler.peakHeap, PeakGoSys: sampler.peakSys, Allocated: final.TotalAlloc - baseline.TotalAlloc, DiskBefore: diskBefore, PeakDisk: sampler.peakDisk, DiskAfter: diskAfter}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("RESOURCE_JSON:%s\n", encoded)
}

type repeatedResourceByte byte

func TestLogicalResourceMeasurement(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested/file"), []byte("bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	count, err := logicalWorkspaceBytes(root)
	if err != nil || count != 5 {
		t.Fatalf("logical bytes: %d %v", count, err)
	}
	sam := &resourceSampler{}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() { defer workers.Done(); sam.heap(); sam.disk(root) }()
	}
	workers.Wait()
	if sam.err != nil || sam.peakDisk != 5 || sam.peakHeap == 0 || sam.peakSys < sam.peakHeap {
		t.Fatalf("sample: %+v", sam)
	}
	if err := os.Symlink(filepath.Join(root, "nested/file"), filepath.Join(root, "link")); err == nil {
		if _, err := logicalWorkspaceBytes(root); err == nil {
			t.Fatal("measurement followed link")
		}
	}
}

func (value repeatedResourceByte) Read(data []byte) (int, error) {
	for index := range data {
		data[index] = byte(value)
	}
	return len(data), nil
}

func writeResourceFile(t *testing.T, path string, size int64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	_, err = io.CopyBuffer(file, io.LimitReader(repeatedResourceByte('x'), size), make([]byte, 32<<10))
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
}

func writeDenseResourceProcesses(t *testing.T, path string) int {
	t.Helper()
	file, err := os.OpenFile(path, os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	writer := bufio.NewWriterSize(file, 64<<10)
	if err := writer.WriteByte('['); err != nil {
		t.Fatal(err)
	}
	written, records := int64(1), 0
	name := strings.Repeat("resource", 64)
	for pid := 1; ; pid++ {
		entry := fmt.Sprintf(`{"pid":%d,"name":%q}`, pid, name)
		if records > 0 {
			entry = "," + entry
		}
		if written+int64(len(entry))+1 > packageio.DefaultLimits().FileBytes {
			break
		}
		if _, err := writer.WriteString(entry); err != nil {
			t.Fatal(err)
		}
		written += int64(len(entry))
		records++
	}
	if err := writer.WriteByte(']'); err != nil {
		t.Fatal(err)
	}
	written++
	_, err = io.Copy(writer, io.LimitReader(repeatedResourceByte(' '), packageio.DefaultLimits().FileBytes-written))
	flushErr, closeErr := writer.Flush(), file.Close()
	if err != nil || flushErr != nil || closeErr != nil {
		t.Fatal(err, flushErr, closeErr)
	}
	return records
}

func TestPackageResourceProfile(t *testing.T) {
	if os.Getenv("IR_PACKAGE_RESOURCE_PROFILE") != "1" {
		t.Skip("opt-in synthetic resource profile")
	}
	for _, scenario := range []string{"payload-limit", "file-count-limit", "dense-domain-limit"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			// Reuse the complete minimal fixture, copying only small JSON files.
			fixture := writeCentralCaseFixture(t, "resource-host", "resource-1")
			files := readPackageTree(t, fixture)
			var initial int64
			for name, data := range files {
				path := filepath.Join(source, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				initial += int64(len(data))
			}
			if err := os.Mkdir(filepath.Join(root, "temporary"), 0700); err != nil {
				t.Fatal(err)
			}
			limits := packageio.DefaultLimits()
			records := 0
			switch scenario {
			case "payload-limit":
				remaining := limits.PayloadBytes - initial
				for index := 0; remaining > 0; index++ {
					size := remaining
					if size > limits.FileBytes {
						size = limits.FileBytes
					}
					writeResourceFile(t, filepath.Join(source, fmt.Sprintf("payload-%03d.bin", index)), size)
					remaining -= size
				}
			case "file-count-limit":
				for index := 0; index < limits.FileCount-len(files); index++ {
					writeResourceFile(t, filepath.Join(source, fmt.Sprintf("extra-%04d.bin", index)), 512)
				}
			case "dense-domain-limit":
				records = writeDenseResourceProcesses(t, filepath.Join(source, "process/processes.json"))
			}
			for _, operation := range []string{"export", "verify", "extract", "import"} {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPackageResourceWorker$")
				for _, value := range os.Environ() {
					if !strings.HasPrefix(value, "IR_PACKAGE_RESOURCE_") {
						cmd.Env = append(cmd.Env, value)
					}
				}
				cmd.Env = append(cmd.Env, "IR_PACKAGE_RESOURCE_WORKER=1", "IR_PACKAGE_RESOURCE_ROOT="+root, "IR_PACKAGE_RESOURCE_OPERATION="+operation, "IR_PACKAGE_RESOURCE_SCENARIO="+scenario)
				cmd.Env = append(cmd.Env, "IR_PACKAGE_RESOURCE_DISK_MODE="+os.Getenv("IR_PACKAGE_RESOURCE_DISK_MODE"))
				output, err := cmd.CombinedOutput()
				deadlineErr := ctx.Err()
				cancel()
				if err != nil || deadlineErr != nil {
					t.Fatalf("worker %s: %v %v\n%s", operation, err, deadlineErr, output)
				}
				var result packageResourceResult
				found := false
				for _, line := range bytes.Split(output, []byte("\n")) {
					if raw, ok := bytes.CutPrefix(line, []byte("RESOURCE_JSON:")); ok {
						if err := json.Unmarshal(raw, &result); err != nil {
							t.Fatal(err)
						}
						found = true
					}
				}
				if !found {
					t.Fatalf("missing resource result: %s", output)
				}
				if scenario == "payload-limit" && result.PayloadBytes != limits.PayloadBytes {
					t.Fatal("not at payload budget")
				}
				if scenario == "file-count-limit" && result.FileCount != limits.FileCount {
					t.Fatal("not at file count budget")
				}
				result.DomainRecords = records
				encoded, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				fmt.Printf("RESOURCE_JSON:%s\n", encoded)
			}
			assertPackageTempEmpty(t, filepath.Join(root, "temporary"))
		})
	}
}
