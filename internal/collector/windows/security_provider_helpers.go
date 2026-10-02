//go:build windows

package windows

import (
	"ir-toolkit/internal/model"
	"strings"
)

func sanitizeSecurityProviderID(
	guid string,
	name string,
) string {

	value :=
		strings.TrimSpace(
			guid,
		)

	if value == "" {
		value = name
	}

	value =
		strings.ToLower(
			value,
		)

	replacer :=
		strings.NewReplacer(
			"{", "",
			"}", "",
			" ", "-",
			`\`, "-",
			"/", "-",
		)

	return replacer.Replace(
		value,
	)
}

func mergeSecurityProviders(
	values []model.SecurityProvider,
) []model.SecurityProvider {

	result :=
		make(
			[]model.SecurityProvider,
			0,
		)

	index :=
		make(
			map[string]int,
		)

	for _, value := range values {

		key :=
			strings.ToLower(
				strings.TrimSpace(
					value.Name,
				),
			)

		if key == "" {
			key = value.ID
		}

		position, exists :=
			index[key]

		if !exists {

			index[key] =
				len(result)

			result =
				append(
					result,
					value,
				)

			continue
		}

		existing :=
			&result[position]

		if existing.Type !=
			value.Type {

			existing.Type =
				existing.Type +
					"+" +
					value.Type
		}
	}

	return result
}
