//go:build windows

package windows

import (
	"context"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/model"
)

const (
	defaultMaxProcessEvents = 5000

	windowedMaxProcessEvents = 30000
)

func collectWindowsProcessEvents(
	ctx context.Context,
) (
	[]model.ProcessEvent,
	[]string,
) {

	result :=
		make(
			[]model.ProcessEvent,
			0,
		)

	window :=
		collection.TimeWindowFromContext(
			ctx,
		)

	maxEvents :=
		defaultMaxProcessEvents

	if !window.Empty() {

		maxEvents =
			windowedMaxProcessEvents
	}

	queryText :=
		buildProcessEventQuery(
			window,
		)

	xmlEvents,
		warnings :=
		queryEventXML(
			ctx,
			"Security",
			queryText,
			maxEvents,
		)

	for _, xmlText := range xmlEvents {

		event, err :=
			parseProcessEventXML(
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

	return result, warnings
}
