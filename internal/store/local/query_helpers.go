package local

import (
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"strconv"
	"strings"
)

const (
	defaultQueryLimit = 100
	maxQueryLimit     = 500
)

type QueryPage struct {
	Offset int

	Limit int
}

func normalizeQueryLimit(
	limit int,
) int {

	switch {

	case limit <= 0:

		return defaultQueryLimit

	case limit > maxQueryLimit:

		return maxQueryLimit

	default:

		return limit
	}
}

func normalizeQueryPage(
	offset int,
	limit int,
	total int,
) QueryPage {

	if offset < 0 {
		offset = 0
	}

	if offset > total {
		offset = total
	}

	return QueryPage{
		Offset: offset,

		Limit: normalizeQueryLimit(
			limit,
		),
	}
}

func queryPageEnd(
	page QueryPage,
	total int,
) int {

	end :=
		page.Offset +
			page.Limit

	if end > total {
		end = total
	}

	return end
}

func buildQueryPageResult(
	page QueryPage,
	end int,
	total int,
) store.QueryPageResult {

	return store.QueryPageResult{
		Offset: page.Offset,

		Limit: page.Limit,

		HasMore: end < total,
	}
}

func processMatchesSearch(
	process model.Process,
	query string,
) bool {

	values :=
		[]string{
			process.Name,
			process.Path,
			process.CommandLine,
			process.User,
			process.AuthenticationID,
			process.IntegrityLevel,
			process.SHA256,
			process.Signer,

			strconv.FormatUint(
				uint64(process.PID),
				10,
			),

			strconv.FormatUint(
				uint64(process.PPID),
				10,
			),
		}

	for _, value := range values {

		if containsFold(
			value,
			query,
		) {

			return true
		}
	}

	return false
}

func timelineEventContains(
	event model.TimelineEvent,
	query string,
) bool {

	values :=
		[]string{
			event.ID,
			event.Category,
			event.Type,
			event.Severity,
			event.Host,
			event.User,
			event.SourceIP,
			event.Process,
			event.Object,
			event.Description,
			strconv.FormatUint(
				uint64(
					event.PID,
				),
				10,
			),
		}

	for _, value := range values {

		if containsFold(
			value,
			query,
		) {

			return true
		}
	}

	for key, value := range event.Metadata {

		if containsFold(
			key,
			query,
		) ||
			containsFold(
				value,
				query,
			) {

			return true
		}
	}

	for _, relatedID := range event.RelatedIDs {

		if containsFold(
			relatedID,
			query,
		) {

			return true
		}
	}

	return false
}

func containsFold(
	value string,
	query string,
) bool {

	return strings.Contains(
		strings.ToLower(
			value,
		),
		strings.ToLower(
			query,
		),
	)
}

func timelineEventMatchesOptions(
	event model.TimelineEvent,
	options store.TimelineQueryOptions,
) bool {

	if options.Category != "" &&
		!strings.EqualFold(
			event.Category,
			options.Category,
		) {

		return false
	}

	if options.PID != 0 &&
		event.PID != options.PID {

		return false
	}

	if options.User != "" &&
		!containsFold(
			event.User,
			options.User,
		) {

		return false
	}

	if options.IP != "" &&
		!containsFold(
			event.SourceIP,
			options.IP,
		) {

		return false
	}

	if options.From != nil &&
		!event.Timestamp.IsZero() &&
		event.Timestamp.Before(
			*options.From,
		) {

		return false
	}

	if options.To != nil &&
		!event.Timestamp.IsZero() &&
		event.Timestamp.After(
			*options.To,
		) {

		return false
	}

	if options.Query != "" &&
		!timelineEventContains(
			event,
			options.Query,
		) {

		return false
	}

	return true
}

func timelineEventMatchesOptionsWithoutCategory(
	event model.TimelineEvent,
	options store.TimelineQueryOptions,
) bool {

	copy :=
		options

	copy.Category =
		""

	return timelineEventMatchesOptions(
		event,
		copy,
	)
}
