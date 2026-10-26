//go:build ignore

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPackageAcceptanceNativeCLI(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Dir(filepath.Dir(file))
	binary := filepath.Join(t.TempDir(), "ir")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/ir")
	build.Dir = repo
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	parent := filepath.Join(t.TempDir(), "parent with spaces")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(parent, "unrelated.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := runPackageAcceptance(binary, parent)
	if err != nil {
		t.Fatalf("acceptance artifacts %s: %v", root, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report acceptanceReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "passed" || report.Failure != "" || len(report.Checks) != 14 || len(report.BinarySHA256) != 64 || report.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		t.Fatalf("report: %+v", report)
	}
	data, err = os.ReadFile(sentinel)
	if err != nil || string(data) != "keep" {
		t.Fatal("parent sentinel changed", err)
	}
	// A fresh root is required even when the same parent is reused.
	second, err := runPackageAcceptance(binary, parent)
	if err != nil || second == root {
		t.Fatalf("second root %q: %v", second, err)
	}
}

func TestPackageAcceptanceFailureRetainsReport(t *testing.T) {
	parent := t.TempDir()
	// A regular non-executable input must be diagnosed as failure to execute,
	// never mistaken for one of the expected native-command rejections.
	fake := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(fake, []byte("invalid executable"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := runPackageAcceptance(fake, parent)
	if err == nil || !strings.Contains(err.Error(), "did not execute") {
		t.Fatalf("%s: %v", root, err)
	}
	data, err := os.ReadFile(filepath.Join(root, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report acceptanceReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "failed" || report.Failure == "" {
		t.Fatalf("report: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(root, "synthetic case", "manifest.json")); err != nil {
		t.Fatal("failure artifacts not retained", err)
	}
	runner := acceptanceRunner{ir: fake, report: acceptanceReport{Root: root}}
	if _, err := runner.command("expected-rejection-not-executed", false, "case-verify", "unused.tar"); err == nil || !strings.Contains(err.Error(), "did not execute") {
		t.Fatalf("a launch failure counted as an expected rejection: %v", err)
	}
}

func TestWindowsPackageLauncherSyntax(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell unavailable; launcher syntax and Windows ACL runtime remain pending")
	}
	_, file, _, _ := runtime.Caller(0)
	launcher := filepath.Join(filepath.Dir(file), "windows-package-acceptance.ps1")
	// Parse without executing the Windows-only launcher or changing ACLs.
	cmd := exec.Command(pwsh, "-NoProfile", "-NonInteractive", "-Command",
		`$tokens=$null; $parseErrors=$null; [void][System.Management.Automation.Language.Parser]::ParseFile($env:IR_ACCEPTANCE_PARSE_PATH,[ref]$tokens,[ref]$parseErrors); if ($parseErrors.Count -ne 0) { $parseErrors | Out-String | Write-Error; exit 1 }`)
	cmd.Env = append(os.Environ(), "IR_ACCEPTANCE_PARSE_PATH="+launcher)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launcher parser: %v\n%s", err, output)
	}
}
