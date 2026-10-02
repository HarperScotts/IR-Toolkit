package analyzer

import (
	"strings"

	"ir-toolkit/internal/model"
)

func normalizeArtifactPath(
	value string,
) string {

	value = strings.TrimSpace(value)

	value = strings.Trim(
		value,
		`"'`,
	)

	value = strings.ReplaceAll(
		value,
		"/",
		`\`,
	)

	return strings.ToLower(value)
}

func isHighRiskFileLocation(
	path string,
) bool {

	value :=
		normalizeArtifactPath(path)

	patterns := []string{
		`\windows\temp\`,
		`\users\public\`,
		`\appdata\local\temp\`,
		`\downloads\`,
		`\desktop\`,
	}

	for _, pattern := range patterns {

		if strings.Contains(
			value,
			pattern,
		) {

			return true
		}
	}

	return false
}

func hasInternetZone(
	file model.FileTriageItem,
) bool {

	value :=
		strings.ToLower(
			file.ZoneIdentifier,
		)

	return strings.Contains(
		value,
		"zoneid=3",
	) ||
		strings.Contains(
			value,
			"zoneid=4",
		)
}

func fileSeverity(
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

func uniqueUint32(
	values []uint32,
) []uint32 {

	seen :=
		make(
			map[uint32]struct{},
			len(values),
		)

	result :=
		make(
			[]uint32,
			0,
			len(values),
		)

	for _, value := range values {

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
