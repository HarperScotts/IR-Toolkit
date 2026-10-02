//go:build windows

package windows

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/collection"
)

func buildGenericWindowsEventQuery(
	eventIDs []uint32,
	window collection.TimeWindow,
) string {

	eventParts :=
		make(
			[]string,
			0,
			len(eventIDs),
		)

	for _, id := range eventIDs {

		eventParts =
			append(
				eventParts,
				fmt.Sprintf(
					"EventID=%d",
					id,
				),
			)
	}

	systemConditions :=
		make(
			[]string,
			0,
		)

	if len(eventParts) > 0 {

		systemConditions =
			append(
				systemConditions,
				"("+
					strings.Join(
						eventParts,
						" or ",
					)+
					")",
			)
	}

	timeConditions :=
		make(
			[]string,
			0,
			2,
		)

	if window.Since != nil {

		timeConditions =
			append(
				timeConditions,
				fmt.Sprintf(
					"@SystemTime >= '%s'",
					formatEventQueryTime(
						*window.Since,
					),
				),
			)
	}

	if window.Until != nil {

		timeConditions =
			append(
				timeConditions,
				fmt.Sprintf(
					"@SystemTime <= '%s'",
					formatEventQueryTime(
						*window.Until,
					),
				),
			)
	}

	if len(timeConditions) > 0 {

		systemConditions =
			append(
				systemConditions,
				fmt.Sprintf(
					"TimeCreated[%s]",
					strings.Join(
						timeConditions,
						" and ",
					),
				),
			)
	}

	if len(systemConditions) == 0 {
		return "*"
	}

	return fmt.Sprintf(
		"*[System[%s]]",
		strings.Join(
			systemConditions,
			" and ",
		),
	)
}
