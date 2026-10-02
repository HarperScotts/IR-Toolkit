//go:build windows

package windows

import "ir-toolkit/internal/model"

func determineCollectionMode(
	value model.AuditCapabilitySnapshot,
) string {

	historicalSources := 0

	if value.LogonAudit.Enabled {
		historicalSources++
	}

	if value.ProcessCreationAudit.Enabled {
		historicalSources++
	}

	if value.PowerShellScriptBlockLogging.Enabled {
		historicalSources++
	}

	if value.DefenderOperational.Available {
		historicalSources++
	}

	if value.Sysmon.Available {
		historicalSources++
	}

	switch {

	case historicalSources == 0:

		return "snapshot_only"

	case historicalSources >= 4:

		return "historical_full"

	default:

		return "historical_partial"
	}
}

func calculateHistoricalCoverage(
	value model.AuditCapabilitySnapshot,
) uint32 {

	total := uint32(5)

	var available uint32

	if value.LogonAudit.Enabled {
		available++
	}

	if value.ProcessCreationAudit.Enabled {
		available++
	}

	if value.PowerShellScriptBlockLogging.Enabled {
		available++
	}

	if value.DefenderOperational.Available {
		available++
	}

	if value.Sysmon.Available {
		available++
	}

	return available *
		100 /
		total
}
