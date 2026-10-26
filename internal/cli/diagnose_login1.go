package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/analyzer"
	linuxcollector "ir-toolkit/internal/collector/linux"
	"ir-toolkit/internal/model"
)

type login1DiagnosticCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type login1DiagnosticReport struct {
	Schema          string                      `json:"schema"`
	AutomatedStatus string                      `json:"automated_status"`
	Acceptance      string                      `json:"real_host_acceptance"`
	Scope           string                      `json:"scope"`
	Inspection      model.LinuxLogin1Inspection `json:"inspection"`
	Analysis        *model.LinuxLogin1Analysis  `json:"analysis"`
	Checks          []login1DiagnosticCheck     `json:"checks"`
	ManualChecks    []string                    `json:"manual_checks"`
	Error           string                      `json:"error,omitempty"`
}

func buildLogin1Diagnostic(ctx context.Context, inspection model.LinuxLogin1Inspection, collectionErr error) login1DiagnosticReport {
	r := login1DiagnosticReport{Schema: "ir-login1-diagnostic-v1", AutomatedStatus: "incomplete", Acceptance: "not_attested", Scope: "Read-only login1 compatibility observation; not proof of complete session coverage, authentication, process identity or real-host acceptance. Contains sensitive raw service data. No installation, service activation, interactive authorization, auth-log collection or system configuration changes.", Inspection: inspection, Checks: []login1DiagnosticCheck{}, ManualChecks: []string{"Record authorized host/distro and tool build identity separately; UID 0 is not required or automatically requested.", "Compare listed session IDs and supported property meanings with an authorized operator's independently known sessions; do not create login activity just for this diagnostic.", "An empty list does not exercise properties or prove no sessions. Missing/denied properties are unknown, never false.", "If naturally occurring session changes are available, capture a second independent report and review changes; evidence IDs are snapshot-local, not stable cross-snapshot session IDs.", "Record permission/version coverage and browser visual acceptance separately. Do not mark real-host acceptance complete from this JSON alone."}}
	if collectionErr != nil {
		r.Error = collectionErr.Error()
	}
	s := inspection.Snapshot
	analysis := analyzer.AnalyzeLogin(ctx, model.LoginSnapshot{LinuxLogin1: &s}, model.NetworkAnalysis{})
	r.Analysis = analysis.LinuxLogin1
	add := func(name, status, detail string) {
		r.Checks = append(r.Checks, login1DiagnosticCheck{Name: name, Status: status, Detail: detail})
	}
	add("platform", map[bool]string{true: "observed", false: "not_exercised"}[inspection.OS == "linux"], inspection.OS+"/"+inspection.Architecture)
	add("busctl_version", inspection.Tool.Status, "Version bytes/hash and errors retained; version text alone is not compatibility proof.")
	for _, method := range []string{"GetId", "GetNameOwner", "ListSessions", "GetAll"} {
		status := "not_exercised"
		count := 0
		for _, call := range s.Calls {
			if call.Method == method {
				count++
				if status != "failed" {
					status = "observed"
				}
				if call.Status != "observed" || call.Error != "" {
					status = "failed"
				}
			}
		}
		add(method, status, fmt.Sprintf("%d retained call(s); inspect per-call errors, not localized stderr heuristics.", count))
	}
	if r.Analysis != nil {
		add("normalization", r.Analysis.Status, fmt.Sprintf("%d conditional service observations; no Windows/SSH session inference.", len(r.Analysis.Observations)))
		if collectionErr == nil && inspection.OS == "linux" && inspection.Tool.Status == "observed" && s.Status == "observed_subset" && r.Analysis.Status == "observed_subset" {
			r.AutomatedStatus = "observed_subset"
		}
	}
	if inspection.OS != "linux" {
		r.AutomatedStatus = "unsupported"
	}
	return r
}

func newLogin1DiagnosticCommand(inspect func(context.Context) (model.LinuxLogin1Inspection, error)) *cobra.Command {
	return &cobra.Command{Use: "diagnose-login1", Short: "Read-only Linux login1 compatibility report (JSON; not acceptance attestation)", Args: cobra.NoArgs, SilenceUsage: true, RunE: func(cmd *cobra.Command, args []string) error {
		inspection, err := inspect(cmd.Context())
		report := buildLogin1Diagnostic(cmd.Context(), inspection, err)
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		if writeErr := encoder.Encode(report); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return fmt.Errorf("login1 diagnostic incomplete: %w", err)
		}
		if report.AutomatedStatus != "observed_subset" {
			return fmt.Errorf("login1 diagnostic incomplete; inspect JSON checks")
		}
		return nil
	}}
}

func init() { rootCmd.AddCommand(newLogin1DiagnosticCommand(linuxcollector.InspectLogin1)) }
