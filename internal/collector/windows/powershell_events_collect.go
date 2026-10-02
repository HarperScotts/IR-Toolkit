//go:build windows

package windows

import (
	"context"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/model"
)

const (
	defaultMaxPowerShellEvents = 5000

	windowedMaxPowerShellEvents = 30000
)

func collectWindowsPowerShellEvents(
	ctx context.Context,
) (
	[]model.PowerShellEvent,
	[]string,
) {

	result :=
		make(
			[]model.PowerShellEvent,
			0,
		)

	window :=
		collection.TimeWindowFromContext(
			ctx,
		)

	maxEvents :=
		defaultMaxPowerShellEvents

	if !window.Empty() {
		maxEvents =
			windowedMaxPowerShellEvents
	}

	queryText :=
		buildPowerShellEventQuery(
			window,
		)

	xmlEvents,
		warnings :=
		queryEventXML(
			ctx,
			"Microsoft-Windows-PowerShell/Operational",
			queryText,
			maxEvents,
		)

	for _, xmlText := range xmlEvents {

		event, err :=
			parsePowerShellEventXML(
				xmlText,
			)

		if err != nil {

			warnings =
				appendUniqueWarning(
					warnings,
					err.Error(),
				)

			continue
		}

		if !window.Empty() &&
			!event.Timestamp.IsZero() &&
			!window.Contains(
				event.Timestamp,
			) {

			continue
		}

		result =
			append(
				result,
				event,
			)
	}

	if len(result) == 0 {

		warnings =
			appendUniqueWarning(
				warnings,
				"no PowerShell Operational Event ID 4103/4104 records were found in the requested time window",
			)
	}

	return result, warnings
}
