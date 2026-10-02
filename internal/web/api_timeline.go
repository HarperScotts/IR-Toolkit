package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

const (
	defaultTimelineLimit = 100
	maxTimelineLimit     = 500
)

type TimelineQueryResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	CategoryCounts map[string]uint32 `json:"category_counts"`

	Events []model.TimelineEvent `json:"events"`
}

type timelineQuery struct {
	Category string

	PID uint32

	User string

	IP string

	Query string

	From *time.Time

	To *time.Time

	Offset int

	Limit int

	Order string
}

func parseTimelineQuery(
	request *http.Request,
) (
	timelineQuery,
	error,
) {

	values :=
		request.URL.Query()

	result :=
		timelineQuery{
			Category: strings.TrimSpace(
				values.Get(
					"category",
				),
			),

			User: strings.TrimSpace(
				values.Get(
					"user",
				),
			),

			IP: strings.TrimSpace(
				values.Get(
					"ip",
				),
			),

			Query: strings.TrimSpace(
				values.Get(
					"q",
				),
			),

			Limit: defaultTimelineLimit,

			Order: "asc",
		}

	// PID

	if value :=
		strings.TrimSpace(
			values.Get(
				"pid",
			),
		); value != "" {

		parsed, err :=
			strconv.ParseUint(
				value,
				10,
				32,
			)

		if err != nil {

			return result,
				fmt.Errorf(
					"invalid pid %q",
					value,
				)
		}

		result.PID =
			uint32(parsed)
	}

	// Offset

	if value :=
		strings.TrimSpace(
			values.Get(
				"offset",
			),
		); value != "" {

		parsed, err :=
			strconv.Atoi(
				value,
			)

		if err != nil ||
			parsed < 0 {

			return result,
				fmt.Errorf(
					"invalid offset %q",
					value,
				)
		}

		result.Offset =
			parsed
	}

	// Limit

	if value :=
		strings.TrimSpace(
			values.Get(
				"limit",
			),
		); value != "" {

		parsed, err :=
			strconv.Atoi(
				value,
			)

		if err != nil ||
			parsed <= 0 {

			return result,
				fmt.Errorf(
					"invalid limit %q",
					value,
				)
		}

		result.Limit =
			parsed
	}

	if result.Limit >
		maxTimelineLimit {

		result.Limit =
			maxTimelineLimit
	}

	// Order

	if value :=
		strings.ToLower(
			strings.TrimSpace(
				values.Get(
					"order",
				),
			),
		); value != "" {

		if value != "asc" &&
			value != "desc" {

			return result,
				fmt.Errorf(
					"invalid order %q",
					value,
				)
		}

		result.Order =
			value
	}

	// From / To

	from, err :=
		parseOptionalRFC3339(
			values.Get(
				"from",
			),
		)

	if err != nil {

		return result,
			fmt.Errorf(
				"invalid from time: %w",
				err,
			)
	}

	result.From =
		from

	to, err :=
		parseOptionalRFC3339(
			values.Get(
				"to",
			),
		)

	if err != nil {

		return result,
			fmt.Errorf(
				"invalid to time: %w",
				err,
			)
	}

	result.To =
		to

	if result.From != nil &&
		result.To != nil &&
		result.From.After(
			*result.To,
		) {

		return result,
			fmt.Errorf(
				"from time is after to time",
			)
	}

	return result, nil
}

func parseOptionalRFC3339(
	value string,
) (
	*time.Time,
	error,
) {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return nil, nil
	}

	parsed, err :=
		time.Parse(
			time.RFC3339Nano,
			value,
		)

	if err != nil {
		return nil, err
	}

	parsed =
		parsed.UTC()

	return &parsed, nil
}

func (s *Server) handleTimeline(
	writer http.ResponseWriter,
	request *http.Request,
) {

	query, err :=
		parseTimelineQuery(
			request,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			err.Error(),
		)

		return
	}

	options :=
		timelineQueryOptionsFromRequestQuery(
			query,
		)

	result,
		err :=
		s.store.QueryTimeline(
			options,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"query timeline: %v",
				err,
			),
		)

		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		TimelineQueryResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			CategoryCounts: result.CategoryCounts,

			Events: result.Events,
		},
	)
}

func timelineQueryOptionsFromRequestQuery(
	query timelineQuery,
) store.TimelineQueryOptions {

	return store.TimelineQueryOptions{
		Category: query.Category,

		PID: query.PID,

		User: query.User,

		IP: query.IP,

		Query: query.Query,

		From: query.From,

		To: query.To,

		Order: query.Order,

		Page: store.QueryPageOptions{
			Offset: query.Offset,

			Limit: query.Limit,
		},
	}
}
