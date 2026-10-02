//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type ProcessEventCollector struct{}

func (c *ProcessEventCollector) Name() string {
	return "windows_process_events"
}

func (c *ProcessEventCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.ProcessEventSnapshot{
			Events: make(
				[]model.ProcessEvent,
				0,
			),

			Warnings: make(
				[]string,
				0,
			),
		}

	events, warnings :=
		collectWindowsProcessEvents(
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

		if event.EventID == 4688 {

			result.Statistics.
				ProcessCreateCount++
		}

		if event.CommandLine != "" {

			result.Statistics.
				WithCommandLineCount++
		}
	}

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"process event collection completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
