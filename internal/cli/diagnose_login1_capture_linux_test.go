//go:build linux && login1integration

package cli

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Explicit fixture-only integration. The caller supplies isolated binaries and
// the expected private-bus state; never silently runs against a developer host.
func TestLogin1AcceptanceCapture(t *testing.T) {
	script, binary, mode := os.Getenv("IR_LOGIN1_CAPTURE_SCRIPT"), os.Getenv("IR_LOGIN1_DIAGNOSTIC_BINARY"), os.Getenv("IR_LOGIN1_TEST_EXPECTATION")
	if script == "" || binary == "" || (mode != "missing" && mode != "synthetic-present" && mode != "synthetic-denied") {
		t.Fatal("explicit isolated capture configuration required")
	}
	output := filepath.Join(t.TempDir(), "private report")
	command := exec.Command("/bin/sh", script, binary, output)
	text, err := command.CombinedOutput()
	if (mode == "synthetic-present") != (err == nil) {
		t.Fatalf("unexpected capture status: %v %s", err, text)
	}
	data, readErr := os.ReadFile(filepath.Join(output, "diagnostic.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	var report login1DiagnosticReport
	if json.Unmarshal(data, &report) != nil || report.Acceptance != "not_attested" || report.Inspection.OS != "linux" || report.Schema != "ir-login1-diagnostic-v1" {
		t.Fatalf("invalid capture: %s", data)
	}
	if mode == "synthetic-present" {
		if report.AutomatedStatus != "observed_subset" || len(report.Analysis.Observations) != 1 || report.Analysis.Observations[0].Properties.Active == nil || *report.Analysis.Observations[0].Properties.Active {
			t.Fatal("successful private fixture lost", report)
		}
	} else if report.AutomatedStatus == "observed_subset" {
		t.Fatal("failure claimed compatibility", report)
	}
	if mode == "synthetic-denied" && report.Inspection.Snapshot.Status != "partial" {
		t.Fatal("denial not retained", report)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("insecure report directory", info, err)
	}
	sums, err := os.ReadFile(filepath.Join(output, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"diagnostic.json", "diagnostic.stderr", "exit-code.txt", "binary-before.sha256", "binary-after.sha256"} {
		data, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(output, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("insecure artifact", name, err)
		}
		if !strings.Contains(string(sums), fmt.Sprintf("%x", sha256.Sum256(data))+"  "+name) {
			t.Fatal("hash manifest mismatch", name)
		}
	}
	before := sha256.Sum256(data)
	if result, err := exec.Command("/bin/sh", script, binary, output).CombinedOutput(); err == nil {
		t.Fatal("existing output overwritten", string(result))
	}
	after, err := os.ReadFile(filepath.Join(output, "diagnostic.json"))
	if err != nil || before != sha256.Sum256(after) {
		t.Fatal("existing report changed", err)
	}
	link := filepath.Join(t.TempDir(), "report-link")
	if err := os.Symlink(output, link); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("/bin/sh", script, binary, link).Run(); err == nil {
		t.Fatal("existing symlink accepted")
	}
}
