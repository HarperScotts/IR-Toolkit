package analyzer

import (
	"ir-toolkit/internal/model"
	"strings"
)

func appendEvidenceGaps(
	report *model.CaseReport,
	capabilities model.AuditCapabilitySnapshot,
	platform string,
) {
	if strings.EqualFold(platform, "linux") {
		for _, warning := range capabilities.Warnings {
			report.EvidenceGaps = append(report.EvidenceGaps, "Linux collection capability: "+warning)
		}
		report.EvidenceGaps = append(report.EvidenceGaps, "Linux audit/journal historical coverage is not established by Windows-specific capability fields; absent events do not establish absence of activity.")
		return
	}

	if !capabilities.SecurityLog.Available {

		report.EvidenceGaps =
			append(
				report.EvidenceGaps,
				"Windows Security event log was unavailable.",
			)
	}

	if !capabilities.LogonAudit.Enabled {

		report.EvidenceGaps =
			append(
				report.EvidenceGaps,
				"Logon auditing was disabled; absence of historical login events does not indicate absence of logon activity.",
			)
	}

	if !capabilities.ProcessCreationAudit.Enabled {

		report.EvidenceGaps =
			append(
				report.EvidenceGaps,
				"Process creation auditing was disabled; 4688 process history coverage is incomplete or unavailable.",
			)
	}

	if !capabilities.
		PowerShellScriptBlockLogging.
		Enabled {

		report.EvidenceGaps =
			append(
				report.EvidenceGaps,
				"PowerShell Script Block Logging was disabled; 4104 coverage is unavailable.",
			)
	}

	if !capabilities.Sysmon.Available {

		report.EvidenceGaps =
			append(
				report.EvidenceGaps,
				"Sysmon telemetry was not available.",
			)
	}
}
