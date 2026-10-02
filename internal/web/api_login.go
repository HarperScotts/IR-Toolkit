package web

import (
	"fmt"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"net/http"
	"strings"
)

type LoginListResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	Sessions []model.LoginSessionAnalysis `json:"sessions"`
}

type LoginDetailResponse struct {
	Session model.LoginSessionAnalysis `json:"session"`
}

func (s *Server) handleLogins(
	writer http.ResponseWriter,
	request *http.Request,
) {

	values :=
		request.URL.Query()

	query :=
		strings.TrimSpace(
			values.Get("q"),
		)

	user :=
		strings.TrimSpace(
			values.Get("user"),
		)

	ip :=
		strings.TrimSpace(
			values.Get("ip"),
		)

	logonType :=
		strings.TrimSpace(
			values.Get("type"),
		)

	offset,
		limit :=
		parseQueryPagination(
			values,
		)

	result,
		err :=
		s.store.QueryLogins(
			store.LoginQueryOptions{
				Query: query,

				User: user,

				IP: ip,

				LogonType: logonType,

				Page: store.QueryPageOptions{
					Offset: offset,

					Limit: limit,
				},
			},
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"query login analysis: %v",
				err,
			),
		)

		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		LoginListResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			Sessions: result.Items,
		},
	)
}

func (s *Server) handleLoginDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	logonID :=
		strings.TrimSpace(
			request.URL.Query().
				Get("id"),
		)

	if logonID == "" {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"id is required",
		)

		return
	}

	session,
		found,
		err :=
		s.store.LoginByLogonID(
			logonID,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load login analysis: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"login session not found",
		)

		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		LoginDetailResponse{
			Session: session,
		},
	)
}
