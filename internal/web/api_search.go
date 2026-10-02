package web

import (
	"fmt"
	"ir-toolkit/internal/store"
	"net/http"
	"strings"
	"time"
)

type InvestigationSearchResult struct {
	Type string `json:"type"`

	ID string `json:"id,omitempty"`

	Title string `json:"title"`

	Subtitle string `json:"subtitle,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	User string `json:"user,omitempty"`

	IP string `json:"ip,omitempty"`

	Object string `json:"object,omitempty"`

	Match string `json:"match,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type InvestigationSearchResponse struct {
	Query string `json:"query"`

	Total uint32 `json:"total"`

	ByType map[string]uint32 `json:"by_type"`

	Results []InvestigationSearchResult `json:"results"`
}

func parseSearchTypes(
	raw string,
) map[string]bool {

	result :=
		make(
			map[string]bool,
		)

	for _, value := range strings.Split(
		raw,
		",",
	) {

		value =
			strings.TrimSpace(
				strings.ToLower(
					value,
				),
			)

		if value == "" {
			continue
		}

		result[value] =
			true
	}

	return result
}

func (s *Server) handleInvestigationSearch(
	writer http.ResponseWriter,
	request *http.Request,
) {

	values :=
		request.URL.Query()

	query :=
		strings.TrimSpace(
			values.Get("q"),
		)

	if query == "" {

		writeJSON(
			writer,
			http.StatusOK,
			InvestigationSearchResponse{
				Query: "",

				Total: 0,

				ByType: map[string]uint32{},

				Results: []InvestigationSearchResult{},
			},
		)

		return
	}

	// ------------------------------------------
	// Limit
	// ------------------------------------------

	limit :=
		parseQueryLimit(
			values.Get("limit"),
		)

	// ------------------------------------------
	// Type Filter
	// ------------------------------------------

	types :=
		parseSearchTypes(
			values.Get("type"),
		)

	// ------------------------------------------
	// Store Query
	// ------------------------------------------

	storeResult,
		err :=
		s.store.SearchInvestigation(
			store.InvestigationSearchOptions{
				Query: query,

				Types: types,

				Limit: limit,
			},
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"search investigation evidence: %v",
				err,
			),
		)

		return
	}

	// ------------------------------------------
	// Store DTO -> Web DTO
	// ------------------------------------------

	results :=
		make(
			[]InvestigationSearchResult,
			0,
			len(storeResult.Items),
		)

	for _, item := range storeResult.Items {

		results =
			append(
				results,
				investigationSearchResultFromStoreItem(
					item,
				),
			)
	}

	writeJSON(
		writer,
		http.StatusOK,
		InvestigationSearchResponse{
			Query: query,

			Total: storeResult.Total,

			ByType: storeResult.ByType,

			Results: results,
		},
	)
}

func investigationSearchResultFromStoreItem(
	item store.InvestigationSearchItem,
) InvestigationSearchResult {

	metadata :=
		make(
			map[string]string,
			len(item.Metadata),
		)

	for key, value := range item.Metadata {

		metadata[key] =
			value
	}

	return InvestigationSearchResult{
		Type: item.Type,

		ID: item.ID,

		Title: item.Title,

		Subtitle: item.Subtitle,

		Timestamp: item.Timestamp,

		PID: item.PID,

		User: item.User,

		IP: item.IP,

		Object: item.Object,

		Match: item.Match,

		Metadata: metadata,
	}
}

