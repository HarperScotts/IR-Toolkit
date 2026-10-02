//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type GenericEventCollector struct{}

func (c *GenericEventCollector) Name() string {
	return "windows_generic_events"
}

func (c *GenericEventCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.WindowsEventSnapshot{
			Definitions: make(
				[]model.WindowsEventDefinitionResult,
				0,
			),

			Events: make(
				[]model.WindowsEvent,
				0,
			),

			Warnings: make(
				[]string,
				0,
			),
		}

	definitions :=
		builtInWindowsEventDefinitions()

	for _, definition := range definitions {

		if !definition.Enabled {
			continue
		}

		select {

		case <-ctx.Done():
			return result, ctx.Err()

		default:
		}

		definitionResult :=
			collectWindowsEventDefinition(
				ctx,
				definition,
			)

		result.Definitions =
			append(
				result.Definitions,
				definitionResult.Result,
			)

		result.Events =
			append(
				result.Events,
				definitionResult.Events...,
			)

		if definitionResult.Warning != "" {

			result.Warnings =
				appendUniqueWarning(
					result.Warnings,
					definitionResult.Warning,
				)
		}
	}

	result.Statistics.DefinitionCount =
		uint32(
			len(definitions),
		)

	for _, definition := range definitions {

		if definition.Enabled {
			result.Statistics.
				EnabledDefinitionCount++
		}
	}

	result.Statistics.EventCount =
		uint32(
			len(result.Events),
		)

	result.Statistics.WarningCount =
		uint32(
			len(result.Warnings),
		)

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"generic Windows event collection completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
