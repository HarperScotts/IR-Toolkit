package analysiscommit

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type countingCancelContext struct {
	context.Context
	checks int
}

func (c *countingCancelContext) Err() error {
	c.checks++
	if c.checks >= 10 {
		return context.Canceled
	}
	return nil
}

func diskFixture(t *testing.T, ioc bool) (string, Commit) {
	t.Helper()
	root := t.TempDir()
	commit := fixtureCommit()
	if ioc {
		entry := File{Path: IOCPath, Size: 2, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("[]")))}
		commit.IOC = &entry
		commit.Inputs = append(commit.Inputs, entry)
		commit.Files = append(commit.Files, entry)
		sort.Slice(commit.Inputs, func(i, j int) bool { return commit.Inputs[i].Path < commit.Inputs[j].Path })
		sort.Slice(commit.Files, func(i, j int) bool { return commit.Files[i].Path < commit.Files[j].Path })
	}
	commit = seal(t, commit)
	for _, file := range commit.Files {
		path := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		var content []byte
		if file.Path == RunPath {
			content, _ = EncodeRun(fixtureRun(), DefaultLimits())
		} else if file.Path == IOCPath {
			content = []byte("[]")
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := EncodeCommit(commit, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, CommitPath), data, 0600); err != nil {
		t.Fatal(err)
	}
	return root, commit
}

func TestVerifyDirectoryInventoryAndLegacy(t *testing.T) {
	for _, ioc := range []bool{false, true} {
		root, c := diskFixture(t, ioc)
		result, err := VerifyDirectory(context.Background(), root, DefaultLimits())
		if err != nil || !result.Managed || result.Run != fixtureRun() || !reflect.DeepEqual(result.Commit, c) || result.FileCount != len(c.Files)+1 {
			t.Fatalf("%+v %v", result, err)
		}
		var expected int64
		for _, file := range c.Files {
			expected += file.Size
		}
		data, _ := os.ReadFile(filepath.Join(root, CommitPath))
		expected += int64(len(data))
		if result.PayloadBytes != expected {
			t.Fatal(result.PayloadBytes, expected)
		}
		// Inputs/outputs here are deliberately empty, invalid domain JSON.
		// Successful byte verification must not imply complete domain loading.
	}
	legacy := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacy, "legacy.json"), []byte("not domain JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := VerifyDirectory(context.Background(), legacy, DefaultLimits())
	if err != nil || r.Managed || !reflect.DeepEqual(r, Verification{}) {
		t.Fatal(r, err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "Analysis-Run.json."), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), legacy, DefaultLimits()); err == nil {
		t.Fatal("portable marker alias fell back to legacy")
	}
}

func TestVerifyDirectoryFailsClosed(t *testing.T) {
	for _, mode := range []string{"missing-run", "missing-commit", "invalid-run", "invalid-commit", "run-mismatch", "changed-file", "missing-file", "extra-file", "extra-directory", "marker-alias", "marker-directory", "symlink", "hardlink", "ioc-injected", "marker-symlink"} {
		t.Run(mode, func(t *testing.T) {
			root, _ := diskFixture(t, false)
			write := func(name string, content []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(root, filepath.FromSlash(name))); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "missing-run":
				remove(RunPath)
			case "missing-commit":
				remove(CommitPath)
			case "invalid-run":
				write(RunPath, []byte(`{"format":"future"}`))
			case "invalid-commit":
				write(CommitPath, []byte(`{}`))
			case "run-mismatch":
				r := fixtureRun()
				r.RunID = strings.Repeat("f", 32)
				data, _ := EncodeRun(r, DefaultLimits())
				write(RunPath, data)
			case "changed-file":
				write("analysis/report.txt", []byte("changed"))
			case "missing-file":
				remove("analysis/report.txt")
			case "extra-file":
				write("extra.txt", []byte("unlisted"))
			case "extra-directory":
				if err := os.Mkdir(filepath.Join(root, "extra"), 0700); err != nil {
					t.Fatal(err)
				}
			case "marker-alias":
				if err := os.Rename(filepath.Join(root, RunPath), filepath.Join(root, "Analysis-Run.json")); err != nil {
					t.Fatal(err)
				}
			case "marker-directory":
				remove(RunPath)
				if err := os.Mkdir(filepath.Join(root, RunPath), 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				remove("analysis/report.txt")
				if err := os.Symlink("../manifest.json", filepath.Join(root, "analysis/report.txt")); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				remove("analysis/report.txt")
				if err := os.Link(filepath.Join(root, "manifest.json"), filepath.Join(root, "analysis/report.txt")); err != nil {
					t.Fatal(err)
				}
			case "ioc-injected":
				write(IOCPath, []byte("[]"))
			case "marker-symlink":
				remove(RunPath)
				if err := os.Symlink("manifest.json", filepath.Join(root, RunPath)); err != nil {
					t.Fatal(err)
				}
			}
			r, err := VerifyDirectory(context.Background(), root, DefaultLimits())
			if err == nil || !reflect.DeepEqual(r, Verification{}) {
				t.Fatal("partial/invalid inventory accepted", r, err)
			}
			if (mode == "missing-run" || mode == "missing-commit") && !errors.Is(err, ErrIncomplete) {
				t.Fatal("incomplete error identity lost", err)
			}
		})
	}
}

func TestVerifyDirectoryLimitsAndCancellation(t *testing.T) {
	root, _ := diskFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyDirectory(ctx, root, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if result, err := VerifyDirectory(&countingCancelContext{Context: context.Background()}, root, DefaultLimits()); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, Verification{}) {
		t.Fatal("mid-verification cancellation leaked partial result", result, err)
	}
	if _, err := VerifyDirectory(nil, root, DefaultLimits()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), filepath.Join(root, "missing"), DefaultLimits()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	for _, kind := range []string{"metadata", "files", "payload", "single"} {
		limits := DefaultLimits()
		switch kind {
		case "metadata":
			limits.MetadataBytes = 32
		case "files":
			limits.FileCount = 26
		case "payload":
			limits.PayloadBytes = 16
		case "single":
			limits.FileBytes = 16
		}
		if _, err := VerifyDirectory(context.Background(), root, limits); !errors.Is(err, ErrLimit) {
			t.Fatal(kind, err)
		}
	}
	file, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.WriteFile(filepath.Join(root, "large"), make([]byte, 1024), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readDiskFile(context.Background(), file, "large", 1, false); !errors.Is(err, ErrLimit) {
		t.Fatal("actual file limit not enforced", err)
	}
}
