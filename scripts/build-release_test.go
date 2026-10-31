//go:build ignore

package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ir-toolkit/internal/buildinfo"
)

func fixtureRelease(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	m := releaseMetadata{Schema: "ir-release-build-v1", Version: buildinfo.Version, Tag: "V" + buildinfo.Version, Commit: strings.Repeat("a", 40), Acceptance: "not_attested"}
	data, _ := json.Marshal(m)
	if err := writeNew(filepath.Join(dir, "BUILDINFO.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	names := []string{"BUILDINFO.json", "RELEASE_NOTES.md", "ir-windows-amd64.exe", "ir-windows-arm64.exe", "ir-toolkit-" + buildinfo.Version + "-linux-amd64.tar.gz", "ir-toolkit-" + buildinfo.Version + "-linux-arm64.tar.gz"}
	for _, name := range names[1:] {
		if err := writeNew(filepath.Join(dir, name), []byte("packaging-test fixture, not a runnable binary"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := checksumManifest(dir, names); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReleaseInventoryAndChecksums(t *testing.T) {
	for _, mode := range []string{"valid", "changed", "missing", "extra", "duplicate", "bad-tag", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			dir := fixtureRelease(t)
			tag := "V" + buildinfo.Version
			switch mode {
			case "changed":
				if err := os.WriteFile(filepath.Join(dir, "ir-windows-amd64.exe"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(filepath.Join(dir, "ir-windows-amd64.exe")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := writeNew(filepath.Join(dir, "unintended-secret.txt"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate":
				path := filepath.Join(dir, "SHA256SUMS.txt")
				data, _ := os.ReadFile(path)
				if err := os.WriteFile(path, append(data, []byte(strings.Split(string(data), "\n")[0]+"\n")...), 0600); err != nil {
					t.Fatal(err)
				}
			case "bad-tag":
				tag = "V../bad"
			case "symlink":
				path := filepath.Join(dir, "BUILDINFO.json")
				if err := os.Rename(path, path+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".old", path); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyReleaseDirectory(dir, tag)
			if (err == nil) != (mode == "valid") {
				t.Fatal(mode, err)
			}
		})
	}
}

func TestReleaseArchiveAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "binary")
	if err := writeNew(binary, []byte("synthetic executable bytes"), 0700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "package.tar.gz")
	if err := createLinuxArchive(archive, "ir-toolkit-test", map[string]string{"ir": binary}); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	header, err := tr.Next()
	if err != nil || header.Name != "ir-toolkit-test/ir" || header.Mode != 0755 || header.Uid != 0 || header.Gid != 0 {
		t.Fatal(header, err)
	}
	data, err := io.ReadAll(tr)
	if err != nil || string(data) != "synthetic executable bytes" {
		t.Fatal(string(data), err)
	}
	if _, err := tr.Next(); err != io.EOF {
		t.Fatal(err)
	}
	if err := createLinuxArchive(archive, "ir-toolkit-test", map[string]string{"ir": binary}); err == nil {
		t.Fatal("existing archive overwritten")
	}
	for i, name := range []string{"../escape", "..", "/absolute", "a\\b"} {
		if err := createLinuxArchive(filepath.Join(dir, string(rune('a'+i))+".tar.gz"), "safe", map[string]string{name: binary}); err == nil {
			t.Fatal("unsafe path accepted", name)
		}
	}
}

func TestReleaseSourceGuards(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git: %v %s", err, output)
		}
	}
	run("init", "-q")
	if err := writeNew(filepath.Join(dir, "source.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	run("add", "source.txt")
	run("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
	run("tag", "V"+buildinfo.Version)
	if _, err := validateReleaseSource(dir, "V"+buildinfo.Version); err != nil {
		t.Fatal(err)
	}
	if err := buildRelease(dir, dir, "V"+buildinfo.Version); err == nil {
		t.Fatal("source-directory output accepted")
	}
	if err := buildRelease(dir, t.TempDir(), "V"+buildinfo.Version); err == nil {
		t.Fatal("existing output directory accepted")
	}
	if _, err := validateReleaseSource(dir, "V99.0.0"); err == nil {
		t.Fatal("version mismatch accepted")
	}
	if err := writeNew(filepath.Join(dir, "dirty.txt"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateReleaseSource(dir, "V"+buildinfo.Version); err == nil {
		t.Fatal("dirty checkout accepted")
	}
	if err := os.Remove(filepath.Join(dir, "dirty.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "info", "exclude"), []byte("*.ignored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeNew(filepath.Join(dir, "leak.ignored"), []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateReleaseSource(dir, "V"+buildinfo.Version); err == nil || !strings.Contains(err.Error(), "ignored") {
		t.Fatal("ignored input not rejected", err)
	}
}
