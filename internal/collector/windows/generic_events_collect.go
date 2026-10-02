//go:build windows

package windows

import (
	"context"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/model"
)

type genericEventDefinitionCollection struct {
	Result model.WindowsEventDefinitionResult

	Events []model.WindowsEvent

	Warning string
}

func collectWindowsEventDefinition(
	ctx context.Context,
	definition WindowsEventDefinition,
) genericEventDefinitionCollection {

	result :=
		genericEventDefinitionCollection{
			Result: model.WindowsEventDefinitionResult{
				ID: definition.ID,

				Channel: definition.Channel,

				RequestedEventIDs: definition.EventIDs,

				Status: "ok",
			},

			Events: make(
				[]model.WindowsEvent,
				0,
			),
		}

	channelStatus :=
		checkEventChannel(
			definition.Channel,
		)

	if !channelStatus.Available {

		result.Result.Status =
			"unavailable"

		result.Warning =
			definition.ID +
				": event channel unavailable"

		result.Result.Warning =
			result.Warning

		return result
	}

	window :=
		collection.TimeWindowFromContext(
			ctx,
		)

	query :=
		buildGenericWindowsEventQuery(
			definition.EventIDs,
			window,
		)

	maxEvents :=
		definition.MaxEvents

	if maxEvents <= 0 {
		maxEvents = 5000
	}

	xmlEvents,
		warnings :=
		queryEventXML(
			ctx,
			definition.Channel,
			query,
			maxEvents,
		)

	for _, xmlText := range xmlEvents {

		event, err :=
			parseGenericWindowsEventXML(
				xmlText,
				definition.ID,
				definition.Channel,
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

		result.Events =
			append(
				result.Events,
				event,
			)
	}

	result.Result.EventCount =
		uint32(
			len(result.Events),
		)

	if len(warnings) > 0 {

		result.Result.Status =
			"warn"

		result.Warning =
			definition.ID +
				": " +
				warnings[0]

		result.Result.Warning =
			result.Warning
	}

	return result
}
