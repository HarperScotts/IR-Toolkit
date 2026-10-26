package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
	"ir-toolkit/internal/store/central"
)

type packageCrashReader struct {
	io.Reader
	count      int
	checkpoint func(string)
}

type packageCrashWriter struct {
	io.Writer
	count      int
	checkpoint func(string)
}

func (w *packageCrashWriter) Write(data []byte) (int, error) {
	if w.count >= 16<<10 {
		w.checkpoint("packing")
	}
	count, err := w.Writer.Write(data)
	w.count += count
	return count, err
}

func (r *packageCrashReader) Read(data []byte) (int, error) {
	// Pause before the next read, after the previous chunk has been written.
	if r.count >= 16<<10 {
		r.checkpoint("extracting")
	}
	count, err := r.Reader.Read(data)
	r.count += count
	return count, err
}

// Environment selectors exist only in this child test helper, never in the
// production importer. The parent owns the subprocess and its temporary data.
func TestPackageCrashHelper(t *testing.T) {
	if os.Getenv("IR_PACKAGE_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	phase := os.Getenv("IR_PACKAGE_CRASH_PHASE")
	block := func(at string) {
		if at != phase {
			return
		}
		fmt.Fprintln(os.Stdout, "checkpoint:"+at)
		var signal [1]byte
		if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
			t.Fatal(err)
		}
		t.Fatal("parent must kill the helper, not resume it")
	}
	if os.Getenv("IR_PACKAGE_CRASH_MODE") == "pack" {
		hooks := packagePackHooks{checkpoint: block}
		if phase == "packing" {
			hooks.writer = func(writer io.Writer) io.Writer { return &packageCrashWriter{Writer: writer, checkpoint: block} }
		}
		_, err := packCaseFileWithHooks(context.Background(), os.Getenv("IR_PACKAGE_CRASH_SOURCE"), os.Getenv("IR_PACKAGE_CRASH_OUTPUT"), hooks)
		t.Fatalf("pack helper completed instead of blocking: %v", err)
	}
	hooks := packageImportHooks{checkpoint: block}
	if phase == "extracting" {
		hooks.reader = func(reader io.Reader) io.Reader { return &packageCrashReader{Reader: reader, checkpoint: block} }
	}
	_, err := importPackageFileWithHooks(context.Background(), os.Getenv("IR_PACKAGE_CRASH_INPUT"),
		os.Getenv("IR_PACKAGE_CRASH_REPOSITORY"), "case", os.Getenv("IR_PACKAGE_CRASH_TEMP"), hooks)
	t.Fatalf("helper completed instead of blocking: %v", err)
}

func TestPackageExportForcedTermination(t *testing.T) {
	for _, phase := range []string{"packing", "completed"} {
		t.Run(phase, func(t *testing.T) {
			source := archiveFixtureSource(t, "alpha", "1").Dir
			if err := os.Mkdir(filepath.Join(source, "aaa"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "aaa/payload.bin"), bytes.Repeat([]byte("evidence"), 12<<10), 0600); err != nil {
				t.Fatal(err)
			}
			before := readPackageTree(t, source)
			output := filepath.Join(t.TempDir(), "interrupted.tar")
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPackageCrashHelper$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "IR_PACKAGE_CRASH_") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "IR_PACKAGE_CRASH_HELPER=1", "IR_PACKAGE_CRASH_MODE=pack", "IR_PACKAGE_CRASH_PHASE="+phase,
				"IR_PACKAGE_CRASH_SOURCE="+source, "IR_PACKAGE_CRASH_OUTPUT="+output)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "checkpoint:"+phase {
				t.Fatalf("pack checkpoint: %q %v", line, err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := cmd.Wait()
			waited = true
			if waitErr == nil || ctx.Err() != nil {
				t.Fatalf("not an intentional pack kill: %v %v", waitErr, ctx.Err())
			}
			data, err := os.ReadFile(output)
			if err != nil || len(data) == 0 {
				t.Fatalf("output did not survive kill: %v", err)
			}
			_, verifyErr := verifyCaseFile(context.Background(), output)
			if phase == "packing" {
				if verifyErr == nil {
					t.Fatal("partial output verified")
				}
			} else if verifyErr != nil {
				t.Fatal("completed pre-receipt output not recoverable", verifyErr)
			}
			if _, err := packCaseFile(context.Background(), source, output); !errors.Is(err, os.ErrExist) {
				t.Fatalf("retry overwrote killed writer output: %v", err)
			}
			after, err := os.ReadFile(output)
			if err != nil || !bytes.Equal(data, after) {
				t.Fatal("retry altered old output")
			}
			if !reflect.DeepEqual(before, readPackageTree(t, source)) {
				t.Fatal("pack kill changed source evidence")
			}
			// Do not recover/remove the interrupted output; explicitly choose a
			// different new path, confined to the parent's temporary fixture tree.
			newOutput := filepath.Join(filepath.Dir(output), "retry-new.tar")
			if _, err := packCaseFile(context.Background(), source, newOutput); err != nil {
				t.Fatal(err)
			}
			if _, err := verifyCaseFile(context.Background(), newOutput); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: interrupted output preserved; explicit new-path retry succeeds without source changes", phase)
		})
	}
}

func packageCrashArtifacts(t *testing.T, repository, parent string) (string, []string) {
	t.Helper()
	roots, err := os.ReadDir(parent)
	if err != nil || len(roots) != 1 || !roots[0].IsDir() || !strings.HasPrefix(roots[0].Name(), "ir-toolkit-extract-") {
		t.Fatalf("expected one extraction orphan: %v %v", roots, err)
	}
	items, err := os.ReadDir(repository)
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	for _, item := range items {
		if strings.HasPrefix(item.Name(), ".stage-") {
			stages = append(stages, filepath.Join(repository, item.Name()))
		}
	}
	return filepath.Join(parent, roots[0].Name()), stages
}

func assertPackageCrashViews(t *testing.T, repository, phase string) {
	t.Helper()
	repo, _, err := archive.Load(repository, loadArchivedSnapshot)
	want := 1
	if phase == "published" {
		want = 2
	}
	if err != nil || repo.Len() != want {
		t.Fatalf("visible views phase=%s want=%d: %v", phase, want, err)
	}
	seed, found := repo.Open(store.CaseView{CaseID: "case", HostID: "existing", Version: "1"})
	if !found {
		t.Fatal("existing committed view lost")
	}
	process, found, err := seed.ProcessByPID(42)
	if err != nil || !found || process.Name != "existing-needle.exe" {
		t.Fatal("existing evidence changed", err)
	}
	newView, found := repo.Open(store.CaseView{CaseID: "case", HostID: "alpha", Version: "1"})
	if phase == "published" {
		if !found {
			t.Fatal("published view not recoverable")
		}
		process, found, err := newView.ProcessByPID(42)
		if err != nil || !found || process.Name != "alpha-needle.exe" {
			t.Fatal("published evidence incomplete", err)
		}
	} else if found {
		t.Fatal("unpublished view visible")
	}
}

func TestPackageForcedTerminationRecovery(t *testing.T) {
	for _, phase := range []string{"extracting", "extracted", "validated", "staged", "published"} {
		t.Run(phase, func(t *testing.T) {
			repository := t.TempDir()
			seed := archiveFixtureSource(t, "existing", "1")
			seed.View.CaseID = "case"
			if err := archive.Commit(repository, []archive.Source{seed}, loadArchivedSnapshot); err != nil {
				t.Fatal(err)
			}
			_, oldEntries, err := archive.Load(repository, loadArchivedSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			oldBytes := readPackageTree(t, oldEntries[0].Dir)
			source := archiveFixtureSource(t, "alpha", "1").Dir
			if err := os.Mkdir(filepath.Join(source, "aaa"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "aaa/payload.bin"), bytes.Repeat([]byte("evidence"), 12<<10), 0600); err != nil {
				t.Fatal(err)
			}
			packet := filepath.Join(t.TempDir(), "case.tar")
			if _, err := packCaseFile(context.Background(), source, packet); err != nil {
				t.Fatal(err)
			}
			inputBefore, err := os.ReadFile(packet)
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPackageCrashHelper$")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "IR_PACKAGE_CRASH_") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "IR_PACKAGE_CRASH_HELPER=1", "IR_PACKAGE_CRASH_PHASE="+phase,
				"IR_PACKAGE_CRASH_INPUT="+packet, "IR_PACKAGE_CRASH_REPOSITORY="+repository, "IR_PACKAGE_CRASH_TEMP="+parent)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			line, err := bufio.NewReader(stdout).ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "checkpoint:"+phase {
				t.Fatalf("checkpoint not reached: %q %v", line, err)
			}
			assertPackageCrashViews(t, repository, phase)
			orphan, stages := packageCrashArtifacts(t, repository, parent)
			payload, err := os.Stat(filepath.Join(orphan, "case/aaa/payload.bin"))
			if err != nil {
				t.Fatal(err)
			}
			if phase == "extracting" {
				if payload.Size() <= 0 || payload.Size() >= 96<<10 {
					t.Fatalf("not a partial extraction: %d", payload.Size())
				}
			} else if payload.Size() != 96<<10 {
				t.Fatalf("complete extraction size: %d", payload.Size())
			}
			lockPath := filepath.Join(repository, ".ingest.lock")
			if phase == "staged" {
				if len(stages) != 1 {
					t.Fatalf("missing staged archive: %v", stages)
				}
				if !reflect.DeepEqual(readPackageTree(t, source), readPackageTree(t, filepath.Join(stages[0], "cases/000000"))) {
					t.Fatal("staged payload not complete")
				}
				if _, err := os.Lstat(filepath.Join(stages[0], "commit.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("staged checkpoint was not before commit manifest")
				}
				if _, err := importPackageFile(context.Background(), packet, repository, "case", parent); !errors.Is(err, archive.ErrWriterBusy) {
					t.Fatalf("live writer lock bypassed: %v", err)
				}
			} else {
				if len(stages) != 0 {
					t.Fatalf("unexpected stage: %v", stages)
				}
				if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected lock: %v", err)
				}
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := cmd.Wait()
			waited = true
			if waitErr == nil || ctx.Err() != nil {
				t.Fatalf("not an intentional kill: %v deadline=%v stderr=%s", waitErr, ctx.Err(), stderr.String())
			}
			assertPackageCrashViews(t, repository, phase)
			orphanAfter, stagesAfter := packageCrashArtifacts(t, repository, parent)
			if orphanAfter != orphan || !reflect.DeepEqual(stagesAfter, stages) {
				t.Fatal("kill unexpectedly cleaned temp/stage state")
			}
			orphanBytes := readPackageTree(t, orphan)
			if !reflect.DeepEqual(oldBytes, readPackageTree(t, oldEntries[0].Dir)) {
				t.Fatal("kill altered existing batch")
			}
			if phase == "staged" {
				lockBefore, err := os.ReadFile(lockPath)
				if err != nil {
					t.Fatal(err)
				}
				lockInfo, err := os.Stat(lockPath)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := importPackageFile(context.Background(), packet, repository, "case", parent); !errors.Is(err, archive.ErrWriterBusy) {
					t.Fatalf("orphan lock bypassed: %v", err)
				}
				lockAfter, err := os.ReadFile(lockPath)
				if err != nil || !bytes.Equal(lockBefore, lockAfter) {
					t.Fatal("orphan lock contents changed")
				}
				afterInfo, err := os.Stat(lockPath)
				if err != nil || !os.SameFile(lockInfo, afterInfo) {
					t.Fatal("orphan lock replaced")
				}
				// Explicit simulated recovery only in t.TempDir: Wait proves the
				// child is dead and archive.Load has validated existing commits.
				if err := os.Rename(lockPath, filepath.Join(t.TempDir(), "preserved-writer.lock")); err != nil {
					t.Fatal(err)
				}
			}
			result, retryErr := importPackageFile(context.Background(), packet, repository, "case", parent)
			if phase == "published" {
				if !errors.Is(retryErr, central.ErrDuplicateView) || result.Committed != nil {
					t.Fatalf("published view overwritten: %+v %v", result, retryErr)
				}
			} else if retryErr != nil || result.Committed == nil || !*result.Committed {
				t.Fatalf("explicit retry: %+v %v", result, retryErr)
			}
			assertPackageCrashViews(t, repository, "published")
			finalOrphan, finalStages := packageCrashArtifacts(t, repository, parent)
			if finalOrphan != orphan || !reflect.DeepEqual(finalStages, stages) || !reflect.DeepEqual(orphanBytes, readPackageTree(t, orphan)) {
				t.Fatal("retry cleaned another invocation's orphan data")
			}
			if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("normal retry retained writer lock")
			}
			inputAfter, err := os.ReadFile(packet)
			if err != nil || !bytes.Equal(inputBefore, inputAfter) {
				t.Fatal("input package modified")
			}
			t.Logf("%s: kill preserved expected orphans; restart/retry respected commit visibility and ownership", phase)
		})
	}
}
