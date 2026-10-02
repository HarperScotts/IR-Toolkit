package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

const maxMultiHostRequestBytes = 1 << 20

type multiHostViewRequest struct {
	CaseID  string `json:"case_id"`
	HostID  string `json:"host_id"`
	Version string `json:"version"`
}

type multiHostViewResponse struct {
	CaseID  string `json:"case_id"`
	HostID  string `json:"host_id"`
	Version string `json:"version"`
}

type multiHostSearchRequest struct {
	Views []multiHostViewRequest `json:"views"`
	Query string                 `json:"query"`
	Types []string               `json:"types,omitempty"`
	Limit int                    `json:"limit,omitempty"`
}

type multiHostSearchResult struct {
	View   multiHostViewResponse     `json:"view"`
	Result InvestigationSearchResult `json:"result"`
}

type multiHostSearchViewSummary struct {
	View   multiHostViewResponse `json:"view"`
	Total  uint32                `json:"total"`
	ByType map[string]uint32     `json:"by_type"`
}

type multiHostSearchResponse struct {
	Query   string                       `json:"query"`
	Total   uint64                       `json:"total"`
	ByType  map[string]uint64            `json:"by_type"`
	ByView  []multiHostSearchViewSummary `json:"by_view"`
	Results []multiHostSearchResult      `json:"results"`
}

type multiHostTimelineRequest struct {
	Views    []multiHostViewRequest `json:"views"`
	Category string                 `json:"category,omitempty"`
	PID      uint32                 `json:"pid,omitempty"`
	User     string                 `json:"user,omitempty"`
	IP       string                 `json:"ip,omitempty"`
	Query    string                 `json:"query,omitempty"`
	From     string                 `json:"from,omitempty"`
	To       string                 `json:"to,omitempty"`
	Offset   int                    `json:"offset,omitempty"`
	Limit    int                    `json:"limit,omitempty"`
	Order    string                 `json:"order,omitempty"`
}

type multiHostTimelineEvent struct {
	View  multiHostViewResponse `json:"view"`
	Event model.TimelineEvent   `json:"event"`
}

type multiHostTimelineViewSummary struct {
	View           multiHostViewResponse `json:"view"`
	Total          uint32                `json:"total"`
	CategoryCounts map[string]uint32     `json:"category_counts"`
}

type multiHostTimelineResponse struct {
	Total          uint64                         `json:"total"`
	Offset         uint32                         `json:"offset"`
	Limit          uint32                         `json:"limit"`
	HasMore        bool                           `json:"has_more"`
	CategoryCounts map[string]uint64              `json:"category_counts"`
	ByView         []multiHostTimelineViewSummary `json:"by_view"`
	Events         []multiHostTimelineEvent       `json:"events"`
}

func (s *Server) handleMultiHostSearch(writer http.ResponseWriter, request *http.Request) {
	var input multiHostSearchRequest
	if err := decodeMultiHostRequest(writer, request, &input); err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	views, err := caseViewsFromRequest(input.Views)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if input.Limit < 0 {
		writeAPIError(writer, http.StatusBadRequest, "limit must not be negative")
		return
	}

	types := make(map[string]bool, len(input.Types))
	for _, evidenceType := range input.Types {
		evidenceType = strings.ToLower(strings.TrimSpace(evidenceType))
		if evidenceType != "" {
			types[evidenceType] = true
		}
	}
	result, err := s.multiHostStore.SearchInvestigation(store.MultiHostSearchOptions{
		Views: views,
		Search: store.InvestigationSearchOptions{
			Query: strings.TrimSpace(input.Query),
			Types: types,
			Limit: input.Limit,
		},
	})
	if err != nil {
		writeMultiHostError(writer, "search multi-host evidence", err)
		return
	}

	response := multiHostSearchResponse{
		Query:   strings.TrimSpace(input.Query),
		Total:   result.Total,
		ByType:  result.ByType,
		ByView:  make([]multiHostSearchViewSummary, 0, len(result.ByView)),
		Results: make([]multiHostSearchResult, 0, len(result.Items)),
	}
	for _, summary := range result.ByView {
		response.ByView = append(response.ByView, multiHostSearchViewSummary{
			View:   multiHostViewResponseFromStore(summary.View),
			Total:  summary.Total,
			ByType: summary.ByType,
		})
	}
	for _, item := range result.Items {
		response.Results = append(response.Results, multiHostSearchResult{
			View:   multiHostViewResponseFromStore(item.View),
			Result: investigationSearchResultFromStoreItem(item.Item),
		})
	}

	writeJSON(writer, http.StatusOK, response)
}

func (s *Server) handleMultiHostTimeline(writer http.ResponseWriter, request *http.Request) {
	var input multiHostTimelineRequest
	if err := decodeMultiHostRequest(writer, request, &input); err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	views, err := caseViewsFromRequest(input.Views)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if input.Offset < 0 || input.Limit < 0 {
		writeAPIError(writer, http.StatusBadRequest, "offset and limit must not be negative")
		return
	}
	order := strings.ToLower(strings.TrimSpace(input.Order))
	if order != "" && order != "asc" && order != "desc" {
		writeAPIError(writer, http.StatusBadRequest, fmt.Sprintf("invalid order %q", input.Order))
		return
	}
	from, err := parseOptionalRFC3339(input.From)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, fmt.Sprintf("invalid from time: %v", err))
		return
	}
	to, err := parseOptionalRFC3339(input.To)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, fmt.Sprintf("invalid to time: %v", err))
		return
	}
	if from != nil && to != nil && from.After(*to) {
		writeAPIError(writer, http.StatusBadRequest, "from time is after to time")
		return
	}

	result, err := s.multiHostStore.QueryTimeline(store.MultiHostTimelineOptions{
		Views: views,
		Query: store.TimelineQueryOptions{
			Category: strings.TrimSpace(input.Category),
			PID:      input.PID,
			User:     strings.TrimSpace(input.User),
			IP:       strings.TrimSpace(input.IP),
			Query:    strings.TrimSpace(input.Query),
			From:     from,
			To:       to,
			Order:    order,
			Page: store.QueryPageOptions{
				Offset: input.Offset,
				Limit:  input.Limit,
			},
		},
	})
	if err != nil {
		writeMultiHostError(writer, "query multi-host timeline", err)
		return
	}

	response := multiHostTimelineResponse{
		Total:          result.Total,
		Offset:         uint32(result.Page.Offset),
		Limit:          uint32(result.Page.Limit),
		HasMore:        result.Page.HasMore,
		CategoryCounts: result.CategoryCounts,
		ByView:         make([]multiHostTimelineViewSummary, 0, len(result.ByView)),
		Events:         make([]multiHostTimelineEvent, 0, len(result.Events)),
	}
	for _, summary := range result.ByView {
		response.ByView = append(response.ByView, multiHostTimelineViewSummary{
			View:           multiHostViewResponseFromStore(summary.View),
			Total:          summary.Total,
			CategoryCounts: summary.CategoryCounts,
		})
	}
	for _, event := range result.Events {
		response.Events = append(response.Events, multiHostTimelineEvent{
			View:  multiHostViewResponseFromStore(event.View),
			Event: event.Event,
		})
	}

	writeJSON(writer, http.StatusOK, response)
}

func decodeMultiHostRequest(writer http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxMultiHostRequestBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("invalid JSON request: multiple values")
		}
		return fmt.Errorf("invalid JSON request: %w", err)
	}

	return nil
}

func caseViewsFromRequest(values []multiHostViewRequest) ([]store.CaseView, error) {
	if len(values) == 0 {
		return nil, errors.New("at least one view is required")
	}

	views := make([]store.CaseView, 0, len(values))
	for _, value := range values {
		view := store.CaseView{
			CaseID:  strings.TrimSpace(value.CaseID),
			HostID:  strings.TrimSpace(value.HostID),
			Version: strings.TrimSpace(value.Version),
		}
		if !view.Valid() {
			return nil, store.ErrInvalidCaseView
		}
		views = append(views, view)
	}

	return views, nil
}

func multiHostViewResponseFromStore(view store.CaseView) multiHostViewResponse {
	return multiHostViewResponse{CaseID: view.CaseID, HostID: view.HostID, Version: view.Version}
}

func writeMultiHostError(writer http.ResponseWriter, action string, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, store.ErrInvalidCaseView),
		errors.Is(err, store.ErrDuplicateCaseView),
		errors.Is(err, store.ErrMixedCases):
		status = http.StatusBadRequest
	case errors.Is(err, store.ErrCaseViewNotFound):
		status = http.StatusNotFound
	}

	writeAPIError(writer, status, fmt.Sprintf("%s: %v", action, err))
}
