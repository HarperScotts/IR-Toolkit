package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultWebQueryLimit = 100
	maxWebQueryLimit     = 500
)

func writeJSON(
	writer http.ResponseWriter,
	status int,
	value any,
) {

	writer.Header().
		Set(
			"Content-Type",
			"application/json; charset=utf-8",
		)

	writer.WriteHeader(
		status,
	)

	encoder :=
		json.NewEncoder(
			writer,
		)

	encoder.SetIndent(
		"",
		"  ",
	)

	_ =
		encoder.Encode(
			value,
		)
}

func writeAPIError(
	writer http.ResponseWriter,
	status int,
	message string,
) {

	writeJSON(
		writer,
		status,
		map[string]any{
			"error": message,
		},
	)
}

func withSecurityHeaders(
	next http.Handler,
) http.Handler {

	return http.HandlerFunc(
		func(
			writer http.ResponseWriter,
			request *http.Request,
		) {

			writer.Header().
				Set(
					"X-Content-Type-Options",
					"nosniff",
				)

			writer.Header().
				Set(
					"X-Frame-Options",
					"DENY",
				)

			writer.Header().
				Set(
					"Referrer-Policy",
					"no-referrer",
				)

			writer.Header().
				Set(
					"Content-Security-Policy",
					"default-src 'self'; "+
						"style-src 'self'; "+
						"script-src 'self'; "+
						"img-src 'self' data:; "+
						"connect-src 'self'; "+
						"object-src 'none'; "+
						"base-uri 'none'; "+
						"frame-ancestors 'none'",
				)

			writer.Header().
				Set(
					"Cache-Control",
					"no-store",
				)

			next.ServeHTTP(
				writer,
				request,
			)
		},
	)
}

func parseNonNegativeInt(
	value string,
	fallback int,
) int {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return fallback
	}

	parsed, err :=
		strconv.Atoi(
			value,
		)

	if err != nil ||
		parsed < 0 {

		return fallback
	}

	return parsed
}

func parsePositiveInt(
	value string,
	fallback int,
) int {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return fallback
	}

	parsed, err :=
		strconv.Atoi(
			value,
		)

	if err != nil ||
		parsed <= 0 {

		return fallback
	}

	return parsed
}

func formatHistoricalUser(
	domain string,
	user string,
) string {

	domain =
		strings.TrimSpace(
			domain,
		)

	user =
		strings.TrimSpace(
			user,
		)

	if user == "" ||
		user == "-" {

		return ""
	}

	if domain == "" ||
		domain == "-" {

		return user
	}

	return domain +
		`\` +
		user
}

func formatEvidenceTime(
	value time.Time,
) string {

	if value.IsZero() {
		return ""
	}

	return value.UTC().
		Format(
			time.RFC3339Nano,
		)
}

func parseQueryPagination(
	values url.Values,
) (
	int,
	int,
) {

	offset :=
		0

	limit :=
		defaultWebQueryLimit

	if raw :=
		values.Get("offset"); raw != "" {

		if value, err :=
			strconv.Atoi(raw); err == nil &&
			value >= 0 {

			offset =
				value
		}
	}

	if raw :=
		values.Get("limit"); raw != "" {

		if value, err :=
			strconv.Atoi(raw); err == nil &&
			value > 0 &&
			value <= maxWebQueryLimit {

			limit =
				value
		}
	}

	return offset,
		limit
}

func parseQueryLimit(
	value string,
) int {

	limit :=
		defaultWebQueryLimit

	if value == "" {
		return limit
	}

	parsed,
		err :=
		strconv.Atoi(
			value,
		)

	if err != nil {
		return limit
	}

	if parsed <= 0 ||
		parsed >
			maxWebQueryLimit {

		return limit
	}

	return parsed
}
