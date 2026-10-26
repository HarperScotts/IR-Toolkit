package archive

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
	"strings"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/central"
)

type crashSnapshot struct {
	store.CaseStore
	payload string
}

func (s *crashSnapshot) ProcessByPID(pid uint32) (model.Process, bool, error) {
	if pid != 42 {
		return model.Process{}, false, nil
	}
	return model.Process{PID: 42, Name: s.payload}, true, nil
}

func crashLoader(view store.CaseView, dir string) (store.CaseStore, error) {
	data, err := os.ReadFile(filepath.Join(dir, "evidence.json"))
	if err != nil {
		return nil, err
	}
	if string(data) != view.HostID {
		return nil, errors.New("fixture identity mismatch")
	}
	return &crashSnapshot{payload: string(data)}, nil
}

func crashSource(t *testing.T, host string) Source {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence.json"), []byte(host), 0600); err != nil {
		t.Fatal(err)
	}
	return Source{View: store.CaseView{CaseID: "case", HostID: host, Version: "1"}, Dir: dir}
}

// This helper only executes in a child test binary. A pipe blocks it exactly at
// a storage boundary while the parent inspects state and forcibly kills it.
func TestArchiveCrashHelper(t *testing.T) {
	if os.Getenv("IR_ARCHIVE_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	phase := os.Getenv("IR_ARCHIVE_CRASH_PHASE")
	root := os.Getenv("IR_ARCHIVE_CRASH_ROOT")
	sources := []Source{
		{View: store.CaseView{CaseID: "case", HostID: "alpha", Version: "1"}, Dir: os.Getenv("IR_ARCHIVE_CRASH_ALPHA")},
		{View: store.CaseView{CaseID: "case", HostID: "beta", Version: "1"}, Dir: os.Getenv("IR_ARCHIVE_CRASH_BETA")},
	}
	block := func(at string) {
		if at != phase {
			return
		}
		fmt.Fprintln(os.Stdout, "checkpoint:"+at)
		var signal [1]byte
		if _, err := io.ReadFull(os.Stdin, signal[:]); err != nil {
			t.Fatalf("checkpoint pipe: %v", err)
		}
		t.Fatal("parent must kill this helper, not resume it")
	}
	loader := func(view store.CaseView, dir string) (store.CaseStore, error) {
		snapshot, err := crashLoader(view, dir)
		if err == nil && view.HostID == "alpha" && strings.Contains(dir, string(os.PathSeparator)+".stage-") {
			block("partial")
		}
		return snapshot, err
	}
	if err := commitBatch(root, sources, loader, block); err != nil {
		t.Fatal(err)
	}
	t.Fatal("helper reached normal completion instead of the checkpoint")
}

func TestArchiveForcedTerminationAndExplicitLockRecovery(t *testing.T) {
	for _, phase := range []string{"partial", "staged", "published"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			seed := crashSource(t, "existing")
			alpha, beta := crashSource(t, "alpha"), crashSource(t, "beta")
			sources := []Source{alpha, beta}
			if err := Commit(root, []Source{seed}, crashLoader); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestArchiveCrashHelper$")
			// Replace only task-specific environment keys; inherited helper flags must
			// not accidentally turn the parent test binary into a recursive helper.
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "IR_ARCHIVE_CRASH_") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "IR_ARCHIVE_CRASH_HELPER=1", "IR_ARCHIVE_CRASH_PHASE="+phase,
				"IR_ARCHIVE_CRASH_ROOT="+root, "IR_ARCHIVE_CRASH_ALPHA="+alpha.Dir, "IR_ARCHIVE_CRASH_BETA="+beta.Dir)
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
				t.Fatalf("helper did not reach %s: %q, %v", phase, line, err)
			}
			assertCrashViews(t, root, phase)
			assertCrashArtifacts(t, root, phase)
			if err := Commit(root, sources, crashLoader); !errors.Is(err, ErrWriterBusy) {
				t.Fatalf("live writer lock not respected: %v", err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			waitErr := cmd.Wait()
			waited = true
			if waitErr == nil || ctx.Err() != nil {
				t.Fatalf("not an intentional forced termination: %v; deadline %v; %s", waitErr, ctx.Err(), stderr.String())
			}
			// Kill bypasses Go defers: the lock must survive and reads must still
			// expose either the old repository or the complete newly committed batch.
			assertCrashViews(t, root, phase)
			assertCrashArtifacts(t, root, phase)
			lockPath := filepath.Join(root, ".ingest.lock")
			lockBefore, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatalf("crashed writer lock disappeared: %v", err)
			}
			lockInfo, err := os.Stat(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := Commit(root, sources, crashLoader); !errors.Is(err, ErrWriterBusy) {
				t.Fatalf("orphan lock not respected: %v", err)
			}
			lockAfter, err := os.ReadFile(lockPath)
			if err != nil || !bytes.Equal(lockBefore, lockAfter) {
				t.Fatal("blocked import modified the orphan lock")
			}
			afterInfo, err := os.Stat(lockPath)
			if err != nil || !os.SameFile(lockInfo, afterInfo) {
				t.Fatal("blocked import replaced the orphan lock")
			}
			// Explicit simulated operator recovery, confined to this test's lock:
			// child Wait has proved the writer is dead, and all commits were verified.
			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			if phase == "published" {
				if err := Commit(root, sources, crashLoader); !errors.Is(err, central.ErrDuplicateView) {
					t.Fatalf("published batch was overwritten on retry: %v", err)
				}
			} else {
				stagesBefore := crashStages(t, root)
				if len(stagesBefore) != 1 {
					t.Fatalf("expected one preserved interrupted stage: %v", stagesBefore)
				}
				if err := Commit(root, sources, crashLoader); err != nil {
					t.Fatal(err)
				}
				stagesAfter := crashStages(t, root)
				if len(stagesAfter) != 1 || stagesAfter[0] != stagesBefore[0] {
					t.Fatal("retry removed another invocation's staging data")
				}
			}
			assertCrashViews(t, root, "published")
			if _, err := os.Stat(lockPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("normal recovery left a lock: %v", err)
			}
			if phase == "published" && len(crashStages(t, root)) != 0 {
				t.Fatal("published batch also retained a staging directory")
			}
			t.Logf("%s: forced termination preserved lock; visible views and explicit retry matched commit boundary", phase)
		})
	}
}

func assertCrashArtifacts(t *testing.T, root, phase string) {
	t.Helper()
	stages := crashStages(t, root)
	if phase == "published" {
		if len(stages) != 0 {
			t.Fatal("rename did not consume staged directory")
		}
		return
	}
	if len(stages) != 1 {
		t.Fatalf("checkpoint staging directories: %v", stages)
	}
	stage := filepath.Join(root, stages[0])
	alpha, err := os.ReadFile(filepath.Join(stage, "cases", "000000", "evidence.json"))
	if err != nil || string(alpha) != "alpha" {
		t.Fatal("first staged source incomplete")
	}
	_, manifestErr := os.Stat(filepath.Join(stage, "commit.json"))
	beta, betaErr := os.ReadFile(filepath.Join(stage, "cases", "000001", "evidence.json"))
	if phase == "partial" {
		if !errors.Is(manifestErr, os.ErrNotExist) || !errors.Is(betaErr, os.ErrNotExist) {
			t.Fatal("partial checkpoint was not before second source/commit")
		}
	} else {
		if manifestErr != nil || betaErr != nil || string(beta) != "beta" {
			t.Fatal("staged checkpoint was not after complete batch preparation")
		}
	}
}

func crashStages(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var stages []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".stage-") {
			stages = append(stages, entry.Name())
		}
	}
	return stages
}

func assertCrashViews(t *testing.T, root, phase string) {
	t.Helper()
	repository, entries, err := Load(root, crashLoader)
	want := 1
	if phase == "published" {
		want = 3
	}
	if err != nil || repository.Len() != want || len(entries) != want {
		t.Fatalf("partial publication at %s: entries=%v, error=%v", phase, entries, err)
	}
	for _, host := range []string{"existing", "alpha", "beta"} {
		snapshot, found := repository.Open(store.CaseView{CaseID: "case", HostID: host, Version: "1"})
		expected := host == "existing" || phase == "published"
		if found != expected {
			t.Fatalf("%s visible=%v at %s", host, found, phase)
		}
		if found {
			process, ok, err := snapshot.ProcessByPID(42)
			if err != nil || !ok || process.Name != host {
				t.Fatalf("corrupt visible evidence: %+v, %v", process, err)
			}
		}
	}
}
