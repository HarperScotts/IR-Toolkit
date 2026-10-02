package local

import "strings"

func searchContains(
	query string,
	values ...string,
) bool {

	query =
		strings.ToLower(
			strings.TrimSpace(
				query,
			),
		)

	if query == "" {
		return false
	}

	for _, value := range values {

		if strings.Contains(
			strings.ToLower(
				value,
			),
			query,
		) {

			return true
		}
	}

	return false
}

func searchTypeEnabled(
	types map[string]bool,
	value string,
) bool {

	if len(types) == 0 {
		return true
	}

	return types[strings.ToLower(
		value)]
}
