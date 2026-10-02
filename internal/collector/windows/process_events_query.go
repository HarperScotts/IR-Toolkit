//go:build windows

package windows

import (
	"fmt"
	"strings"
	"time"

	"ir-toolkit/internal/collection"
)

func buildProcessEventQuery(
	window collection.TimeWindow,
) string {

	conditions :=
		[]string{
			"(EventID=4688)",
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

		conditions =
			append(
				conditions,
				fmt.Sprintf(
					"TimeCreated[%s]",
					strings.Join(
						timeConditions,
						" and ",
					),
				),
			)
	}

	return fmt.Sprintf(
		"*[System[%s]]",
		strings.Join(
			conditions,
			" and ",
		),
	)
}

func formatProcessEventQueryTime(
	value time.Time,
) string {

	return value.UTC().
		Format(
			"2006-01-02T15:04:05.000000000Z",
		)
}
