//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type CapabilityCollector struct{}

func (c *CapabilityCollector) Name() string {
	return "windows_capabilities"
}

func (c *CapabilityCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.AuditCapabilitySnapshot{
			Warnings: make(
				[]string,
				0,
			),
		}

	result.SecurityLog =
		checkEventChannel(
			"Security",
		)

	result.PowerShellOperational =
		checkEventChannel(
			"Microsoft-Windows-PowerShell/Operational",
		)

	result.DefenderOperational =
		checkEventChannel(
			"Microsoft-Windows-Windows Defender/Operational",
		)

	result.Sysmon =
		checkSysmonCapability()

	result.LogonAudit =
		checkAuditSubcategory(
			"{0CCE9215-69AE-11D9-BED3-505054503030}",
		)

	result.ProcessCreationAudit =
		checkAuditSubcategory(
			"{0CCE922B-69AE-11D9-BED3-505054503030}",
		)

	result.ProcessCreationEvents =
		checkProcessCreationEventCapability(
			ctx,
			result.SecurityLog,
			result.ProcessCreationAudit,
		)

	result.PowerShellScriptBlockLogging =
		checkPowerShellScriptBlockLogging()

	result.CollectionMode =
		determineCollectionMode(
			result,
		)

	result.HistoricalCoverage =
		calculateHistoricalCoverage(
			result,
		)

	result.SnapshotCoverage = 100

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"capability detection completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
