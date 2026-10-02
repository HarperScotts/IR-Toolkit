//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type PowerShellEventCollector struct{}

func (c *PowerShellEventCollector) Name() string {
	return "windows_powershell_events"
}

func (c *PowerShellEventCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.PowerShellEventSnapshot{
			Events: make(
				[]model.PowerShellEvent,
				0,
			),

			Warnings: make(
				[]string,
				0,
			),
		}

	events, warnings :=
		collectWindowsPowerShellEvents(
			ctx,
		)

	result.Events =
		events

	result.Warnings =
		warnings

	result.Statistics.EventCount =
		uint32(
			len(events),
		)

	for _, event := range events {

		switch event.EventID {

		case 4103:
			result.Statistics.
				ModuleLoggingCount++

		case 4104:
			result.Statistics.
				ScriptBlockCount++
		}

		if event.ScriptBlockText != "" {
			result.Statistics.
				ScriptTextCount++
		}
	}

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"PowerShell event collection completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
