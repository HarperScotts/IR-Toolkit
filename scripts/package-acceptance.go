//go:build ignore

// Run explicitly with go run scripts/package-acceptance.go. This black-box
// harness touches only a new private child of the selected work parent.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

type acceptanceReport struct {
	Status       string   `json:"status"`
	Root         string   `json:"root"`
	Platform     string   `json:"platform"`
	GoVersion    string   `json:"go_version"`
	BinarySHA256 string   `json:"binary_sha256"`
	Started      string   `json:"started_utc"`
	Checks       []string `json:"checks"`
	Failure      string   `json:"failure,omitempty"`
}

type acceptanceRunner struct {
	ir     string
	report acceptanceReport
}

func main() {
	ir := flag.String("ir", "", "existing native IR executable")
	parent := flag.String("work-parent", "", "existing trusted private parent; outputs are retained")
	flag.Parse()
	root, err := runPackageAcceptance(*ir, *parent)
	if root != "" {
		fmt.Printf("Acceptance artifacts retained: %s\n", root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runPackageAcceptance(ir, parent string) (root string, err error) {
	if ir == "" || parent == "" {
		return "", errors.New("-ir and -work-parent are required")
	}
	ir, err = filepath.Abs(ir)
	if err != nil {
		return "", err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(ir)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("IR executable must be a regular non-symlink file")
	}
	info, err = os.Lstat(parent)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("work parent must be a real, trusted private directory")
	}
	root, err = os.MkdirTemp(parent, "ir-package-acceptance-")
	if err != nil {
		return "", err
	}
	runner := acceptanceRunner{ir: ir, report: acceptanceReport{Status: "failed", Root: root,
		Platform: runtime.GOOS + "/" + runtime.GOARCH, GoVersion: runtime.Version(), Started: time.Now().UTC().Format(time.RFC3339), Checks: []string{}}}
	defer func() {
		if err != nil {
			runner.report.Failure = err.Error()
		}
		data, marshalErr := json.MarshalIndent(runner.report, "", "  ")
		if marshalErr == nil {
			marshalErr = os.WriteFile(filepath.Join(root, "result.json"), append(data, '\n'), 0600)
		}
		err = errors.Join(err, marshalErr)
	}()
	binary, err := os.ReadFile(ir)
	if err != nil {
		return root, err
	}
	runner.report.BinarySHA256 = acceptanceHash(binary)
	err = runner.run()
	if err == nil {
		runner.report.Status = "passed"
	}
	return root, err
}

func acceptanceHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// No shell parsing; exact arguments, separate stdout/stderr and exit status.
// Timeout retains all artifacts, including any uncertain commit state.
func (r *acceptanceRunner) command(name string, success bool, args ...string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.ir, args...)
	cmd.Dir = r.report.Root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	meta, _ := json.MarshalIndent(map[string]any{"args": args, "exit_code": code, "expected_success": success}, "", "  ")
	for suffix, data := range map[string][]byte{"stdout.txt": stdout.Bytes(), "stderr.txt": stderr.Bytes(), "command.json": meta} {
		if logErr := os.WriteFile(filepath.Join(r.report.Root, name+"."+suffix), data, 0600); logErr != nil {
			return nil, logErr
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%s timed out; inspect retained artifacts before retrying: %w", name, ctx.Err())
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, fmt.Errorf("%s did not execute: %w", name, err)
		}
	}
	if success != (err == nil) {
		return nil, fmt.Errorf("%s unexpected exit %d: %s", name, code, stderr.String())
	}
	var receipt map[string]any
	if success {
		if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
			return nil, fmt.Errorf("%s receipt: %w", name, err)
		}
	}
	r.report.Checks = append(r.report.Checks, name)
	return receipt, nil
}

func acceptanceFixture(root string) error {
	raw := "synthetic raw evidence 原始字节\r\n"
	files := map[string]string{
		"manifest.json":                  `{"case_id":"acceptance-version-1","hostname":"acceptance-host","files":[]}`,
		"host/host.json":                 `{"hostname":"acceptance-host"}`,
		"process/processes.json":         `[{"pid":42,"name":"synthetic.exe"}]`,
		"capabilities/capabilities.json": `{}`, "files/files.json": `{}`, "persistence/persistence.json": `{}`,
		"analysis/login_analysis.json": `{}`, "analysis/network_analysis.json": `{}`,
		"analysis/process_history_analysis.json": `{}`, "analysis/powershell_analysis.json": `{}`,
		"analysis/windows_event_analysis.json": `{}`, "analysis/ioc_matches.json": `{}`,
		"analysis/historical_correlation.json": `{}`, "timeline/timeline.json": `{}`,
		"raw/evidence.txt": raw,
	}
	manifest, err := json.Marshal(map[string]any{"case_id": "acceptance-version-1", "hostname": "acceptance-host",
		"files": []map[string]any{{"path": "raw/evidence.txt", "size": len([]byte(raw)), "sha256": acceptanceHash([]byte(raw))}}})
	if err != nil {
		return err
	}
	files["manifest.json"] = string(manifest)
	for path, text := range files {
		path = filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			return err
		}
	}
	return nil
}

func acceptanceInventory(root string) (map[string]string, error) {
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected symlink in acceptance tree")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = acceptanceHash(data)
		return nil
	})
	return files, err
}

func acceptanceEmpty(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("temporary extraction not cleaned: %s", path)
	}
	return nil
}

func (r *acceptanceRunner) run() error {
	root := r.report.Root
	source := filepath.Join(root, "synthetic case")
	parent := filepath.Join(root, "private extraction")
	repo := filepath.Join(root, "repository")
	packet := filepath.Join(root, "case package.ircase.tar")
	if err := acceptanceFixture(source); err != nil {
		return err
	}
	if err := os.Mkdir(parent, 0700); err != nil {
		return err
	}
	original, err := acceptanceInventory(source)
	if err != nil {
		return err
	}
	pack, err := r.command("01-pack", true, "case-pack", source, "--output", packet)
	if err != nil {
		return err
	}
	if pack["status"] != "exported" || pack["domains_loaded"] != true || pack["committed"] != false || pack["host_id"] != "acceptance-host" || pack["version"] != "acceptance-version-1" || pack["case_name"] != "synthetic case" || pack["file_count"] != float64(len(original)) {
		return errors.New("unexpected export identity/count/state")
	}
	verify, err := r.command("02-verify", true, "case-verify", packet)
	if err != nil {
		return err
	}
	if verify["status"] != "verified-framing-source" || verify["domains_loaded"] != false || verify["committed"] != false || verify["content_digest"] != pack["content_digest"] {
		return errors.New("unexpected verification state/digest")
	}
	packetBytes, err := os.ReadFile(packet)
	if err != nil {
		return err
	}
	if _, err := r.command("03-no-overwrite", false, "case-pack", source, "--output", packet); err != nil {
		return err
	}
	after, err := os.ReadFile(packet)
	if err != nil || !bytes.Equal(after, packetBytes) {
		return errors.Join(errors.New("existing package changed"), err)
	}
	inside := filepath.Join(source, "forbidden.tar")
	if _, err := r.command("04-no-output-in-source", false, "case-pack", source, "--output", inside); err != nil {
		return err
	}
	if _, err := os.Lstat(inside); !errors.Is(err, os.ErrNotExist) {
		return errors.New("in-source output was created")
	}
	importArgs := func(input, destination string) []string {
		return []string{"central-import-package", "--repository", destination, "--case-id", "receiving-acceptance", "--temp-parent", parent, input}
	}
	for _, mutation := range []string{"corrupted", "truncated"} {
		data := append([]byte{}, packetBytes...)
		if mutation == "corrupted" {
			position := bytes.Index(data, []byte("synthetic raw evidence"))
			if position < 0 {
				return errors.New("raw fixture payload not found")
			}
			data[position] ^= 1
		} else {
			data = data[:len(data)-513]
		}
		bad := filepath.Join(root, mutation+".tar")
		if err := os.WriteFile(bad, data, 0600); err != nil {
			return err
		}
		if _, err := r.command("05-verify-"+mutation, false, "case-verify", bad); err != nil {
			return err
		}
		badRepo := filepath.Join(root, mutation+"-repository")
		if _, err := r.command("06-import-"+mutation, false, importArgs(bad, badRepo)...); err != nil {
			return err
		}
		if _, err := os.Lstat(badRepo); !errors.Is(err, os.ErrNotExist) {
			return errors.New("invalid input created a repository")
		}
		if err := acceptanceEmpty(parent); err != nil {
			return err
		}
		unchanged, err := os.ReadFile(bad)
		if err != nil || !bytes.Equal(unchanged, data) {
			return errors.Join(errors.New("invalid input package changed"), err)
		}
	}
	badSource := filepath.Join(root, "invalid domain case")
	if err := acceptanceFixture(badSource); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(badSource, "process", "processes.json"), []byte(`{"broken":`), 0600); err != nil {
		return err
	}
	badOutput := filepath.Join(root, "invalid-domain.tar")
	if _, err := r.command("07-pack-domain-failure", false, "case-pack", badSource, "--output", badOutput); err != nil {
		return err
	}
	if _, err := os.Lstat(badOutput); !errors.Is(err, os.ErrNotExist) {
		return errors.New("failed export left output")
	}
	imported, err := r.command("08-import", true, importArgs(packet, repo)...)
	if err != nil {
		return err
	}
	wantView := map[string]any{"case_id": "receiving-acceptance", "host_id": "acceptance-host", "version": "acceptance-version-1"}
	if imported["status"] != "committed" || imported["committed"] != true || imported["content_digest"] != pack["content_digest"] || imported["case_name"] != pack["case_name"] || !reflect.DeepEqual(imported["view"], wantView) {
		return errors.New("unexpected committed view/state")
	}
	if err := acceptanceEmpty(parent); err != nil {
		return err
	}
	entries, err := os.ReadDir(repo)
	if err != nil {
		return err
	}
	if len(entries) != 1 || !entries[0].IsDir() || !strings.HasPrefix(entries[0].Name(), "batch-") {
		return errors.New("unexpected archive entries after import")
	}
	batch := filepath.Join(repo, entries[0].Name())
	var commit struct {
		Version int `json:"version"`
		Entries []struct {
			View map[string]any `json:"view"`
			Name string         `json:"name"`
			Dir  string         `json:"dir"`
		} `json:"entries"`
		Files map[string]string `json:"files"`
	}
	data, err := os.ReadFile(filepath.Join(batch, "commit.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &commit); err != nil {
		return err
	}
	if commit.Version != 1 || len(commit.Entries) != 1 || commit.Entries[0].Dir != "000000" || commit.Entries[0].Name != "synthetic case" || !reflect.DeepEqual(commit.Entries[0].View, wantView) {
		return errors.New("unexpected archive commit")
	}
	archived := filepath.Join(batch, "cases", "000000")
	archivedFiles, err := acceptanceInventory(archived)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(archivedFiles, original) {
		return errors.New("archived evidence bytes changed")
	}
	commitFiles, err := acceptanceInventory(filepath.Join(batch, "cases"))
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(commitFiles, commit.Files) {
		return errors.New("commit inventory mismatch")
	}
	r.report.Checks = append(r.report.Checks, "archive-byte-and-commit-inventory")
	repoBefore, err := acceptanceInventory(repo)
	if err != nil {
		return err
	}
	if _, err := r.command("09-reject-duplicate", false, importArgs(packet, repo)...); err != nil {
		return err
	}
	repoAfter, err := acceptanceInventory(repo)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(repoBefore, repoAfter) {
		return errors.New("duplicate import changed repository")
	}
	entriesAfter, err := os.ReadDir(repo)
	if err != nil {
		return err
	}
	if len(entriesAfter) != 1 || entriesAfter[0].Name() != entries[0].Name() || !entriesAfter[0].IsDir() {
		return errors.New("duplicate import retained a lock/stage or changed batch layout")
	}
	if err := acceptanceEmpty(parent); err != nil {
		return err
	}
	// A fresh process reloads all domains from archived bytes, not source/cache.
	reloaded, err := r.command("10-reload-archived-case", true, "case-pack", archived, "--output", filepath.Join(root, "archived-reload.tar"))
	if err != nil {
		return err
	}
	if reloaded["status"] != "exported" || reloaded["domains_loaded"] != true || reloaded["committed"] != false || reloaded["host_id"] != pack["host_id"] || reloaded["version"] != pack["version"] || reloaded["file_count"] != pack["file_count"] {
		return errors.New("archived domain reload identity/state mismatch")
	}
	sourceAfter, err := acceptanceInventory(source)
	if err != nil {
		return err
	}
	inputAfter, err := os.ReadFile(packet)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(original, sourceAfter) || !bytes.Equal(packetBytes, inputAfter) {
		return errors.New("source or input package changed")
	}
	r.report.Checks = append(r.report.Checks, "source-and-input-unchanged")
	sort.Strings(r.report.Checks)
	return nil
}
