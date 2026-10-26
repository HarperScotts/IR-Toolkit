package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/testutil"
)

func TestLogin1DiagnosticCommand(t *testing.T) {
	for _, mode := range []string{"observed", "empty", "partial", "malformed", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			source := testutil.Login1Snapshot()
			inspection := model.LinuxLogin1Inspection{OS: "linux", Architecture: "arm64", EffectiveUID: 65534, Snapshot: source, Tool: model.LinuxLogin1ToolProbe{Status: "observed", Executable: "/usr/bin/busctl", Arguments: []string{"--version"}, Content: []byte("systemd test fixture")}}
			var inspectErr error
			switch mode {
			case "empty":
				inspection.Snapshot.Sessions = []model.LinuxLogin1Session{}
				inspection.Snapshot.Calls = append(inspection.Snapshot.Calls[:3:3], inspection.Snapshot.Calls[5:]...)
				testutil.Login1SetContent(&inspection.Snapshot.Calls[2], `{"type":"a(susso)","data":[[]]}`)
			case "partial":
				inspection.Snapshot.Status = "partial"
				inspection.Snapshot.Calls[3].Status = "error"
				inspection.Snapshot.Calls[3].Error = "denied"
				inspectErr = errors.New("synthetic denied")
			case "malformed":
				inspection.Snapshot.Calls[2].SHA256 = "bad"
			case "unsupported":
				inspection.OS = "darwin"
				inspection.Snapshot.Status = "unsupported"
				inspectErr = errors.New("requires Linux")
			}
			before, _ := json.Marshal(inspection)
			var stdout bytes.Buffer
			cmd := newLogin1DiagnosticCommand(func(context.Context) (model.LinuxLogin1Inspection, error) { return inspection, inspectErr })
			cmd.SetOut(&stdout)
			cmd.SetErr(io.Discard)
			cmd.SetArgs([]string{})
			err := cmd.Execute()
			var report login1DiagnosticReport
			if json.Unmarshal(stdout.Bytes(), &report) != nil || report.Schema != "ir-login1-diagnostic-v1" || report.Acceptance != "not_attested" || len(report.ManualChecks) == 0 {
				t.Fatalf("invalid JSON report: %s", stdout.String())
			}
			if mode == "observed" || mode == "empty" {
				if err != nil || report.AutomatedStatus != "observed_subset" {
					t.Fatal(report, err)
				}
			} else if err == nil || report.AutomatedStatus == "observed_subset" {
				t.Fatal("incomplete became success", report, err)
			}
			if mode == "empty" {
				for _, check := range report.Checks {
					if check.Name == "GetAll" && check.Status != "not_exercised" {
						t.Fatal("empty list claimed property coverage")
					}
				}
			}
			after, _ := json.Marshal(inspection)
			if !bytes.Equal(before, after) {
				t.Fatal("diagnostic mutated source")
			}
		})
	}
}

func TestLogin1DiagnosticRejectsArgumentsBeforeInspection(t *testing.T) {
	cmd := newLogin1DiagnosticCommand(func(context.Context) (model.LinuxLogin1Inspection, error) {
		t.Fatal("unexpected inspection")
		return model.LinuxLogin1Inspection{}, nil
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--address=untrusted"})
	if cmd.Execute() == nil {
		t.Fatal("address override accepted")
	}
}
