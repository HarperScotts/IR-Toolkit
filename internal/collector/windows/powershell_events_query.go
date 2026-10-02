//go:build windows

package windows

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/collection"
)

func buildPowerShellEventQuery(
	window collection.TimeWindow,
) string {

	conditions :=
		[]string{
			"(EventID=4103 or EventID=4104)",
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
