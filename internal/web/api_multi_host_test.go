package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type multiHostStoreStub struct {
	searchOptions   store.MultiHostSearchOptions
	searchResult    store.MultiHostSearchResult
	searchErr       error
	timelineOptions store.MultiHostTimelineOptions
	timelineResult  store.MultiHostTimelineResult
	timelineErr     error
}

func (s *multiHostStoreStub) SearchInvestigation(options store.MultiHostSearchOptions) (store.MultiHostSearchResult, error) {
	s.searchOptions = options
	return s.searchResult, s.searchErr
}

func (s *multiHostStoreStub) QueryTimeline(options store.MultiHostTimelineOptions) (store.MultiHostTimelineResult, error) {
	s.timelineOptions = options
	return s.timelineResult, s.timelineErr
}

func TestMultiHostSearchHandlerMapsStoreResult(t *testing.T) {
	view := store.CaseView{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	snapshotTime := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	backend := &multiHostStoreStub{searchResult: store.MultiHostSearchResult{
		Total:  3,
		ByType: map[string]uint64{"process": 3},
		ByView: []store.MultiHostViewSearchSummary{{View: view, Total: 3, ByType: map[string]uint32{"process": 3}}},
		Items: []store.MultiHostSearchItem{{
			View: view,
			Item: store.InvestigationSearchItem{
				Type:      "process",
				ID:        "process:42",
				Title:     "needle.exe",
				Timestamp: snapshotTime,
				PID:       42,
			},
		}},
	}}
	server := &Server{multiHostStore: backend}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/multi-host/search",
		strings.NewReader(`{"views":[{"case_id":"case-1","host_id":"host-1","version":"version-1"}],"query":" needle ","types":[" Process "],"limit":7}`),
	)
	recorder := httptest.NewRecorder()

	server.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	if backend.searchOptions.Search.Query != "needle" || !backend.searchOptions.Search.Types["process"] || backend.searchOptions.Search.Limit != 7 {
		t.Fatalf("store options = %#v", backend.searchOptions)
	}
	if len(backend.searchOptions.Views) != 1 || backend.searchOptions.Views[0] != view {
		t.Fatalf("store views = %#v", backend.searchOptions.Views)
	}

	var response multiHostSearchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 3 || response.ByType["process"] != 3 || len(response.Results) != 1 {
		t.Fatalf("response = %#v", response)
	}
	if response.Results[0].View.HostID != "host-1" || response.Results[0].Result.ID != "process:42" {
		t.Fatalf("scoped result = %#v", response.Results[0])
	}
}

func TestMultiHostTimelineHandlerMapsFiltersAndResult(t *testing.T) {
	view := store.CaseView{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	eventTime := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	backend := &multiHostStoreStub{timelineResult: store.MultiHostTimelineResult{
		Total:          2,
		Page:           store.QueryPageResult{Offset: 1, Limit: 1, HasMore: false},
		CategoryCounts: map[string]uint64{"process": 2},
		ByView: []store.MultiHostTimelineViewSummary{{
			View:           view,
			Total:          2,
			CategoryCounts: map[string]uint32{"process": 2},
		}},
		Events: []store.MultiHostTimelineEvent{{
			View:  view,
			Event: model.TimelineEvent{ID: "event:1", Timestamp: eventTime, Category: "process"},
		}},
	}}
	server := &Server{multiHostStore: backend}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/multi-host/timeline",
		strings.NewReader(`{"views":[{"case_id":"case-1","host_id":"host-1","version":"version-1"}],"category":" process ","pid":42,"user":" alice ","query":" needle ","from":"2026-01-01T00:00:00Z","to":"2026-01-03T00:00:00Z","offset":1,"limit":1,"order":"DESC"}`),
	)
	recorder := httptest.NewRecorder()

	server.routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	query := backend.timelineOptions.Query
	if query.Category != "process" || query.PID != 42 || query.User != "alice" || query.Query != "needle" || query.Order != "desc" {
		t.Fatalf("timeline options = %#v", backend.timelineOptions)
	}
	if query.From == nil || query.To == nil || query.Page.Offset != 1 || query.Page.Limit != 1 {
		t.Fatalf("timeline range/page = %#v", query)
	}

	var response multiHostTimelineResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 2 || response.Offset != 1 || response.Limit != 1 || len(response.Events) != 1 {
		t.Fatalf("response = %#v", response)
	}
	if response.Events[0].View.HostID != "host-1" || response.Events[0].Event.ID != "event:1" {
		t.Fatalf("scoped event = %#v", response.Events[0])
	}
}

func TestMultiHostHandlersValidateRequests(t *testing.T) {
	backend := &multiHostStoreStub{}
	server := &Server{multiHostStore: backend}
	tests := []struct {
		name string
		path string
		body string
	}{
		{name: "unknown field", path: "/api/multi-host/search", body: `{"views":[],"unknown":true}`},
		{name: "missing views", path: "/api/multi-host/search", body: `{"query":"needle"}`},
		{name: "negative search limit", path: "/api/multi-host/search", body: `{"views":[{"case_id":"c","host_id":"h","version":"v"}],"limit":-1}`},
		{name: "invalid timeline order", path: "/api/multi-host/timeline", body: `{"views":[{"case_id":"c","host_id":"h","version":"v"}],"order":"sideways"}`},
		{name: "reversed timeline range", path: "/api/multi-host/timeline", body: `{"views":[{"case_id":"c","host_id":"h","version":"v"}],"from":"2026-01-02T00:00:00Z","to":"2026-01-01T00:00:00Z"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, tt.path, strings.NewReader(tt.body))
			recorder := httptest.NewRecorder()
			server.routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestMultiHostHandlerMapsStoreErrors(t *testing.T) {
	viewBody := `{"views":[{"case_id":"case-1","host_id":"host-1","version":"version-1"}],"query":"needle"}`
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "invalid scope", err: store.ErrMixedCases, wantStatus: http.StatusBadRequest},
		{name: "missing view", err: store.ErrCaseViewNotFound, wantStatus: http.StatusNotFound},
		{name: "backend failure", err: errors.New("database unavailable"), wantStatus: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := &Server{multiHostStore: &multiHostStoreStub{searchErr: tt.err}}
			request := httptest.NewRequest(http.MethodPost, "/api/multi-host/search", strings.NewReader(viewBody))
			recorder := httptest.NewRecorder()
			server.routes().ServeHTTP(recorder, request)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", recorder.Code, tt.wantStatus, recorder.Body.String())
			}
		})
	}
}
