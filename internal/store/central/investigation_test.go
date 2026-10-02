package central

import (
	"errors"
	"testing"
	"time"

	"ir-toolkit/internal/store"
)

type searchSnapshotStub struct {
	store.CaseStore

	result store.InvestigationSearchStoreResult
	err    error
	limit  int
}

func (s *searchSnapshotStub) SearchInvestigation(options store.InvestigationSearchOptions) (store.InvestigationSearchStoreResult, error) {
	s.limit = options.Limit
	if s.err != nil {
		return store.InvestigationSearchStoreResult{}, s.err
	}

	result := s.result
	result.Items = append([]store.InvestigationSearchItem(nil), result.Items...)
	if len(result.Items) > options.Limit {
		result.Items = result.Items[:options.Limit]
	}
	return result, nil
}

func TestInvestigatorSearchAggregatesHostsWithoutRewritingEvidenceID(t *testing.T) {
	t1 := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-2", Version: "version-1"}
	snapshot1 := &searchSnapshotStub{result: store.InvestigationSearchStoreResult{
		Total:  2,
		ByType: map[string]uint32{"process": 2},
		Items: []store.InvestigationSearchItem{
			{Type: "process", ID: "process:42", Title: "host-1 recent", Timestamp: t2},
			{Type: "process", ID: "process:7", Title: "host-1 old", Timestamp: t1},
		},
	}}
	snapshot2 := &searchSnapshotStub{result: store.InvestigationSearchStoreResult{
		Total:  2,
		ByType: map[string]uint32{"process": 1, "network": 1},
		Items: []store.InvestigationSearchItem{
			{Type: "process", ID: "process:42", Title: "host-2 recent", Timestamp: t2.Add(time.Hour)},
			{Type: "network", ID: "network:42:tcp:a:1:b:2:connection", Title: "host-2 zero"},
		},
	}}

	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.IngestBatch(
		IngestRequest{View: view1, Snapshot: snapshot1},
		IngestRequest{View: view2, Snapshot: snapshot2},
	); err != nil {
		t.Fatal(err)
	}
	investigator, err := NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}

	result, err := investigator.SearchInvestigation(InvestigationSearchOptions{
		Views: []View{view1, view2},
		Search: store.InvestigationSearchOptions{
			Query: "needle",
			Limit: 3,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 4 || len(result.Items) != 3 {
		t.Fatalf("search totals = %d/%d, want 4/3", result.Total, len(result.Items))
	}
	if result.ByType["process"] != 3 || result.ByType["network"] != 1 {
		t.Fatalf("ByType = %#v, want process=3 network=1", result.ByType)
	}
	if len(result.ByView) != 2 || result.ByView[0].Total != 2 || result.ByView[1].Total != 2 {
		t.Fatalf("ByView = %#v", result.ByView)
	}
	if result.Items[0].View != view2 || result.Items[1].View != view1 {
		t.Fatalf("global order views = %#v", result.Items)
	}
	if result.Items[0].Item.ID != "process:42" || result.Items[1].Item.ID != "process:42" {
		t.Fatalf("evidence IDs were rewritten: %#v", result.Items)
	}
	if result.Items[2].Item.Timestamp.IsZero() {
		t.Fatalf("zero timestamp entered limited results before non-zero item: %#v", result.Items)
	}
	if snapshot1.limit != 3 || snapshot2.limit != 3 {
		t.Fatalf("per-view limits = %d/%d, want 3/3", snapshot1.limit, snapshot2.limit)
	}
}

func TestInvestigatorSearchValidatesScopeBeforeQuery(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	investigator, err := NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}

	tests := []struct {
		name    string
		views   []View
		wantErr error
	}{
		{name: "invalid view", views: []View{{CaseID: "case-1", HostID: "host-1"}}, wantErr: ErrInvalidView},
		{name: "duplicate view", views: []View{view, view}, wantErr: ErrDuplicateView},
		{name: "mixed cases", views: []View{view, {CaseID: "case-2", HostID: "host-2", Version: "version-1"}}, wantErr: ErrMixedCases},
		{name: "missing view", views: []View{view}, wantErr: ErrViewNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := investigator.SearchInvestigation(InvestigationSearchOptions{Views: tt.views, Search: store.InvestigationSearchOptions{Query: "needle"}})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SearchInvestigation() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestInvestigatorSearchReturnsNoPartialResultsOnBackendError(t *testing.T) {
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-2", Version: "version-1"}
	backendError := errors.New("backend unavailable")
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.IngestBatch(
		IngestRequest{View: view1, Snapshot: &searchSnapshotStub{result: store.InvestigationSearchStoreResult{Total: 1}}},
		IngestRequest{View: view2, Snapshot: &searchSnapshotStub{err: backendError}},
	); err != nil {
		t.Fatal(err)
	}
	investigator, err := NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}

	result, err := investigator.SearchInvestigation(InvestigationSearchOptions{
		Views:  []View{view1, view2},
		Search: store.InvestigationSearchOptions{Query: "needle"},
	})
	if !errors.Is(err, backendError) {
		t.Fatalf("SearchInvestigation() error = %v, want wrapped backend error", err)
	}
	if result.Total != 0 || len(result.Items) != 0 || len(result.ByView) != 0 {
		t.Fatalf("partial result escaped after error: %#v", result)
	}
}

func TestNormalizeInvestigationLimit(t *testing.T) {
	tests := map[int]int{
		-1:                        defaultInvestigationLimit,
		0:                         defaultInvestigationLimit,
		1:                         1,
		maxInvestigationLimit:     maxInvestigationLimit,
		maxInvestigationLimit + 1: maxInvestigationLimit,
	}
	for input, want := range tests {
		if got := normalizeInvestigationLimit(input); got != want {
			t.Fatalf("normalizeInvestigationLimit(%d) = %d, want %d", input, got, want)
		}
	}
}
