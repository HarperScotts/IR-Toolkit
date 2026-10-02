package ioc

import (
	"net"
	"strings"
)

func normalizeHash(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}

func normalizePath(
	value string,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	value =
		strings.Trim(
			value,
			`"'`,
		)

	value =
		strings.ReplaceAll(
			value,
			"/",
			`\`,
		)

	return strings.ToLower(
		value,
	)
}

func normalizeProcessName(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}

func normalizeDomain(
	value string,
) string {

	value =
		strings.ToLower(
			strings.TrimSpace(
				value,
			),
		)

	return strings.TrimSuffix(
		value,
		".",
	)
}

func normalizeIP(
	value string,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	ip :=
		net.ParseIP(
			value,
		)

	if ip == nil {
		return value
	}

	return ip.String()
}

func matchString(
	actual string,
	rule string,
	matchType string,
	caseInsensitive bool,
) bool {

	actual =
		strings.TrimSpace(
			actual,
		)

	rule =
		strings.TrimSpace(
			rule,
		)

	if actual == "" ||
		rule == "" {

		return false
	}

	if caseInsensitive {

		actual =
			strings.ToLower(
				actual,
			)

		rule =
			strings.ToLower(
				rule,
			)
	}

	switch strings.ToLower(
		strings.TrimSpace(
			matchType,
		),
	) {

	case "",
		"exact":

		return actual == rule

	case "contains":

		return strings.Contains(
			actual,
			rule,
		)

	case "prefix":

		return strings.HasPrefix(
			actual,
			rule,
		)

	case "suffix":

		return strings.HasSuffix(
			actual,
			rule,
		)

	default:

		return false
	}
}

func normalizeMatchType(
	value string,
) string {

	value =
		strings.ToLower(
			strings.TrimSpace(
				value,
			),
		)

	if value == "" {
		return "exact"
	}

	return value
}
