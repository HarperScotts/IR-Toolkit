package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

type PowerShellEventCollector struct{}

func (c *PowerShellEventCollector) Name() string {
	return "linux_powershell_events"
}

func (c *PowerShellEventCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.PowerShellEventSnapshot{
			Warnings: []string{
				"PowerShell event collection is not implemented on Linux",
			},
		}

	return result,
		fmt.Errorf(
			"PowerShell event collection is not implemented on Linux",
		)
}
