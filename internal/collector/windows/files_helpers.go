//go:build windows

package windows

func uniqueWarningStrings(
	values []string,
) []string {

	seen :=
		make(
			map[string]struct{},
			len(values),
		)

	result :=
		make(
			[]string,
			0,
			len(values),
		)

	for _, value := range values {

		if value == "" {
			continue
		}

		if _, exists :=
			seen[value]; exists {

			continue
		}

		seen[value] =
			struct{}{}

		result =
			append(
				result,
				value,
			)
	}

	return result
}
