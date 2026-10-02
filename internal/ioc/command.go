package ioc

import "strings"

func extractPersistenceExecutable(
	command string,
) string {

	value :=
		strings.TrimSpace(
			command,
		)

	if value == "" {
		return ""
	}

	if strings.HasPrefix(
		value,
		`"`,
	) {

		end :=
			strings.Index(
				value[1:],
				`"`,
			)

		if end >= 0 {

			return value[1 : end+1]
		}
	}

	fields :=
		strings.Fields(
			value,
		)

	if len(fields) == 0 {
		return ""
	}

	return strings.Trim(
		fields[0],
		`"'`,
	)
}
