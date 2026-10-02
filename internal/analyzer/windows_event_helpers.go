package analyzer

import (
	"fmt"
	"strconv"
	"strings"

	"ir-toolkit/internal/model"
)

func windowsEventData(
	event model.WindowsEvent,
	names ...string,
) string {

	for _, name := range names {

		for key, value := range event.Data {

			if strings.EqualFold(
				key,
				name,
			) {

				return strings.TrimSpace(
					value,
				)
			}
		}
	}

	return ""
}

func windowsEventUint32(
	event model.WindowsEvent,
	names ...string,
) uint32 {

	value :=
		windowsEventData(
			event,
			names...,
		)

	if value == "" {
		return 0
	}

	value =
		strings.TrimSpace(
			value,
		)

	base := 10

	if strings.HasPrefix(
		strings.ToLower(value),
		"0x",
	) {

		base = 16

		value =
			value[2:]
	}

	parsed, err :=
		strconv.ParseUint(
			value,
			base,
			32,
		)

	if err != nil {
		return 0
	}

	return uint32(parsed)
}

func windowsActivityID(
	event model.WindowsEvent,
	suffix string,
) string {

	return fmt.Sprintf(
		"win-event:%s:%d:%d:%s",
		sanitizeFindingID(
			event.DefinitionID,
		),
		event.EventID,
		event.RecordID,
		sanitizeFindingID(
			suffix,
		),
	)
}

func windowsEventSeverity(
	score int,
) string {

	switch {

	case score >= 90:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}
