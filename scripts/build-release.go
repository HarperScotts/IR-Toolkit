//go:build ignore

// Builds a fresh release directory from a clean, exactly tagged Git checkout.
// Never uploads or publishes; the workflow creates a draft only after checks.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"ir-toolkit/internal/buildinfo"
)

type releaseMetadata struct {
	Schema     string   `json:"schema"`
	Version    string   `json:"version"`
	Tag        string   `json:"tag"`
	Commit     string   `json:"commit"`
	GoVersion  string   `json:"go_version"`
	BuildFlags []string `json:"build_flags"`
	Acceptance string   `json:"real_host_acceptance"`
}

func gitOutput(root string, args ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", args[0], err)
	}
	return strings.TrimSpace(string(output)), nil
}

func validateReleaseSource(root, tag string) (releaseMetadata, error) {
	m := releaseMetadata{Schema: "ir-release-build-v1", Version: buildinfo.Version, Tag: tag, BuildFlags: []string{"-trimpath", "-buildvcs=false", "CGO_ENABLED=0"}, Acceptance: "not_attested"}
	if !regexp.MustCompile(`^V[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(tag) || tag != "V"+buildinfo.Version {
		return m, fmt.Errorf("tag must exactly match application version V%s", buildinfo.Version)
	}
	status, err := gitOutput(root, "status", "--porcelain", "--untracked-files=normal")
	if err != nil {
		return m, err
	}
	if status != "" {
		return m, fmt.Errorf("release requires a clean source checkout")
	}
	ignored, err := gitOutput(root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
	if err != nil {
		return m, err
	}
	if ignored != "" {
		return m, fmt.Errorf("release checkout contains ignored files; use a fresh isolated checkout")
	}
	m.Commit, err = gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		return m, err
	}
	commit, err := gitOutput(root, "rev-parse", "--verify", "refs/tags/"+tag+"^{commit}")
	if err != nil {
		return m, err
	}
	if commit != m.Commit {
		return m, fmt.Errorf("tag does not identify current source commit")
	}
	version, err := exec.Command("go", "version").Output()
	if err != nil {
		return m, err
	}
	m.GoVersion = strings.TrimSpace(string(version))
	return m, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func createLinuxArchive(output, top string, files map[string]string) (resultErr error) {
	f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); resultErr == nil {
			resultErr = err
		}
	}()
	gz := gzip.NewWriter(f)
	defer func() {
		if err := gz.Close(); resultErr == nil {
			resultErr = err
		}
	}()
	tw := tar.NewWriter(gz)
	defer func() {
		if err := tw.Close(); resultErr == nil {
			resultErr = err
		}
	}()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.Contains(name, "\\") || strings.HasPrefix(name, "/") || strings.Contains(name, "../") || filepath.ToSlash(filepath.Clean(name)) != name {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		info, err := os.Lstat(files[name])
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive input must be regular: %s", name)
		}
		data, err := os.ReadFile(files[name])
		if err != nil {
			return err
		}
		mode := int64(0644)
		if name == "ir" {
			mode = 0755
		}
		if err := tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: mode, Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func checksumManifest(directory string, names []string) error {
	sort.Strings(names)
	var lines strings.Builder
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&lines, "%x  %s\n", sum, name)
	}
	return writeNew(filepath.Join(directory, "SHA256SUMS.txt"), []byte(lines.String()), 0600)
}

func verifyReleaseDirectory(directory, tag string) error {
	if !regexp.MustCompile(`^V[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(tag) {
		return fmt.Errorf("invalid release tag")
	}
	for _, name := range []string{"BUILDINFO.json", "SHA256SUMS.txt"} {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release metadata must be regular")
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "BUILDINFO.json"))
	if err != nil {
		return err
	}
	var metadata releaseMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}
	if metadata.Schema != "ir-release-build-v1" || metadata.Tag != tag || metadata.Version != strings.TrimPrefix(tag, "V") || metadata.Acceptance != "not_attested" || !regexp.MustCompile(`^[0-9a-f]{40,64}$`).MatchString(metadata.Commit) {
		return fmt.Errorf("invalid build metadata")
	}
	expected := map[string]bool{"BUILDINFO.json": true, "RELEASE_NOTES.md": true, "ir-windows-amd64.exe": true, "ir-windows-arm64.exe": true, "ir-toolkit-" + metadata.Version + "-linux-amd64.tar.gz": true, "ir-toolkit-" + metadata.Version + "-linux-arm64.tar.gz": true}
	manifest, err := os.ReadFile(filepath.Join(directory, "SHA256SUMS.txt"))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || !expected[parts[1]] || seen[parts[1]] {
			return fmt.Errorf("unexpected/duplicate checksum entry")
		}
		sum, err := hex.DecodeString(parts[0])
		if err != nil || len(sum) != 32 {
			return fmt.Errorf("invalid checksum")
		}
		path := filepath.Join(directory, parts[1])
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("release asset must be regular")
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got := sha256.Sum256(content)
		if !bytes.Equal(sum, got[:]) {
			return fmt.Errorf("checksum mismatch: %s", parts[1])
		}
		seen[parts[1]] = true
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("missing release assets")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	if len(entries) != len(expected)+1 {
		return fmt.Errorf("unexpected release directory entries")
	}
	return nil
}

func buildRelease(root, output, tag string) error {
	metadata, err := validateReleaseSource(root, tag)
	if err != nil {
		return err
	}
	absoluteOutput, err := filepath.Abs(output)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, absoluteOutput)
	if err != nil {
		return err
	}
	if relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("release output must be outside source checkout")
	}
	if err := os.Mkdir(output, 0700); err != nil {
		return fmt.Errorf("output must be a new directory: %w", err)
	}
	work, err := os.MkdirTemp("", "ir-release-work-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work) // Only this invocation's newly generated scratch tree.
	assets := []string{"BUILDINFO.json", "RELEASE_NOTES.md"}
	info, _ := json.MarshalIndent(metadata, "", "  ")
	if err := writeNew(filepath.Join(output, "BUILDINFO.json"), append(info, '\n'), 0600); err != nil {
		return err
	}
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return err
	}
	var selected []string
	capturing := false
	matches := 0
	for _, line := range strings.Split(string(changelog), "\n") {
		if strings.HasPrefix(line, "## ") {
			fields := strings.Fields(line)
			capturing = len(fields) > 1 && fields[1] == metadata.Version
			if capturing {
				matches++
			}
		}
		if capturing {
			selected = append(selected, line)
		}
	}
	if matches != 1 {
		return fmt.Errorf("CHANGELOG must contain exactly one section for %s", metadata.Version)
	}
	notes := fmt.Sprintf("# IR-Toolkit %s\n\nSource commit: `%s`.\n\n%s\n\nWindows amd64/arm64 executables and Linux amd64/arm64 static archives. Verify all files against SHA256SUMS.txt.\n\nCross-compilation/CI success does not attest real-host acceptance. Real logind distro/permission/session coverage remains unverified; utmp/wtmp/btmp are opaque, and Linux file triage/audit/journal history remain incomplete. See the tagged CHANGELOG and docs/linux-support.md for scope.\n", metadata.Version, metadata.Commit, strings.Join(selected, "\n"))
	if err := writeNew(filepath.Join(output, "RELEASE_NOTES.md"), []byte(notes), 0600); err != nil {
		return err
	}
	for _, platform := range []string{"windows", "linux"} {
		for _, arch := range []string{"amd64", "arm64"} {
			name := "ir-windows-" + arch + ".exe"
			binary := filepath.Join(output, name)
			if platform == "linux" {
				binary = filepath.Join(work, "ir-linux-"+arch)
			}
			command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binary, "./cmd/ir")
			command.Dir = root
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "GOOS=") && !strings.HasPrefix(value, "GOARCH=") && !strings.HasPrefix(value, "CGO_ENABLED=") {
					command.Env = append(command.Env, value)
				}
			}
			command.Env = append(command.Env, "GOOS="+platform, "GOARCH="+arch, "CGO_ENABLED=0")
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			if err := command.Run(); err != nil {
				return err
			}
			if platform == "linux" {
				top := "ir-toolkit-" + metadata.Version + "-linux-" + arch
				name = top + ".tar.gz"
				guide := filepath.Join(work, "LINUX-README.md")
				if arch == "amd64" {
					if err := writeNew(guide, []byte(fmt.Sprintf("# IR-Toolkit %s Linux\n\nRun ./ir --version; ./ir collect --output /new/case; ./ir analyze /new/case; ./ir web /new/case. Use authorized hosts only. Web defaults to 127.0.0.1:8080. Do not reuse cases or elevate automatically. login1 needs existing /usr/bin/busctl and local system bus; unavailable sources remain gaps, not absence. Real-host acceptance is not attested. See docs/linux-support.md and LICENSE.\n", metadata.Version)), 0600); err != nil {
						return err
					}
				}
				files := map[string]string{"ir": binary, "LICENSE": filepath.Join(root, "LICENSE"), "LINUX-README.md": guide, "linux-login1-acceptance.sh": filepath.Join(root, "scripts/linux-login1-acceptance.sh")}
				for _, doc := range []string{"linux-support.md", "linux-login-sources.md", "linux-login1-acceptance.md", "runtime-acceptance.md"} {
					files["docs/"+doc] = filepath.Join(root, "docs", doc)
				}
				if err := createLinuxArchive(filepath.Join(output, name), top, files); err != nil {
					return err
				}
			}
			assets = append(assets, name)
		}
	}
	if err := checksumManifest(output, assets); err != nil {
		return err
	}
	after, err := validateReleaseSource(root, tag)
	if err != nil {
		return err
	}
	if after.Commit != metadata.Commit {
		return fmt.Errorf("source commit changed during release build")
	}
	return verifyReleaseDirectory(output, tag)
}

func main() {
	tag := flag.String("tag", "", "exact Vx.y.z tag")
	output := flag.String("output", "", "new output directory")
	verify := flag.Bool("verify", false, "verify an existing generated directory without building")
	flag.Parse()
	var err error
	if flag.NArg() != 0 || *tag == "" || *output == "" {
		err = fmt.Errorf("usage: go run scripts/build-release.go --tag Vx.y.z --output NEW_DIRECTORY [--verify]")
	} else if *verify {
		err = verifyReleaseDirectory(*output, *tag)
	} else {
		root, e := os.Getwd()
		if e != nil {
			err = e
		} else {
			err = buildRelease(root, *output, *tag)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	_, _ = io.WriteString(os.Stdout, "Release directory verified; real-host acceptance not attested.\n")
}
