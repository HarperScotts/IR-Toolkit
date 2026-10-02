package windows

import "strings"

func normalizeEventLogonID(
	value string,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" ||
		value == "-" {

		return ""
	}

	return strings.ToLower(
		value,
	)
}
