package central

import (
	"errors"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type timelineSnapshotStub struct {
	store.CaseStore

	events         []model.TimelineEvent
	categoryCounts map[string]uint32
	err            error
	pageLimits     []int
}

func (s *timelineSnapshotStub) QueryTimeline(options store.TimelineQueryOptions) (store.TimelineQueryResult, error) {
	if s.err != nil {
		return store.TimelineQueryResult{}, s.err
	}
	s.pageLimits = append(s.pageLimits, options.Page.Limit)

	start := options.Page.Offset
	if start > len(s.events) {
		start = len(s.events)
	}
	end := start + options.Page.Limit
	if end > len(s.events) {
		end = len(s.events)
	}

	return store.TimelineQueryResult{
		Total:          uint32(len(s.events)),
		CategoryCounts: cloneCategoryCounts(s.categoryCounts),
		Page: store.QueryPageResult{
			Offset:  start,
			Limit:   options.Page.Limit,
			HasMore: end < len(s.events),
		},
		Events: append([]model.TimelineEvent(nil), s.events[start:end]...),
	}, nil
}

func TestInvestigatorTimelineAggregatesSortsAndPaginatesHosts(t *testing.T) {
	t1 := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	t3 := t2.Add(time.Hour)
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-2", Version: "version-1"}
	snapshot1 := &timelineSnapshotStub{
		events: []model.TimelineEvent{
			{ID: "event:shared", Timestamp: t1, Category: "process"},
			{ID: "event:host-1", Timestamp: t3, Category: "login"},
		},
		categoryCounts: map[string]uint32{"process": 1, "login": 1},
	}
	snapshot2 := &timelineSnapshotStub{
		events: []model.TimelineEvent{
			{ID: "event:shared", Timestamp: t2, Category: "process"},
			{ID: "event:zero", Category: "network"},
		},
		categoryCounts: map[string]uint32{"process": 1, "network": 1},
	}
	investigator := newTimelineInvestigator(t, map[View]store.CaseStore{
		view1: snapshot1,
		view2: snapshot2,
	})

	result, err := investigator.QueryTimeline(MultiHostTimelineOptions{
		Views: []View{view1, view2},
		Query: store.TimelineQueryOptions{
			Page: store.QueryPageOptions{Offset: 1, Limit: 2},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 4 || len(result.Events) != 2 || !result.Page.HasMore {
		t.Fatalf("timeline totals = %d/%d, has_more=%v, want 4/2/true", result.Total, len(result.Events), result.Page.HasMore)
	}
	if result.CategoryCounts["process"] != 2 || result.CategoryCounts["login"] != 1 || result.CategoryCounts["network"] != 1 {
		t.Fatalf("CategoryCounts = %#v", result.CategoryCounts)
	}
	if len(result.ByView) != 2 || result.ByView[0].Total != 2 || result.ByView[1].Total != 2 {
		t.Fatalf("ByView = %#v", result.ByView)
	}
	if result.Events[0].Event.ID != "event:shared" || result.Events[0].View != view2 {
		t.Fatalf("first paged event = %#v, want host-2 shared event", result.Events[0])
	}
	if result.Events[1].Event.ID != "event:host-1" || result.Events[1].View != view1 {
		t.Fatalf("second paged event = %#v, want host-1 event", result.Events[1])
	}
	if result.Events[0].Event.ID != "event:shared" {
		t.Fatal("timeline evidence ID was rewritten")
	}
}

func TestInvestigatorTimelineFetchesLargeGlobalOffsetInBoundedPages(t *testing.T) {
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	events := make([]model.TimelineEvent, 501)
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	for index := range events {
		events[index] = model.TimelineEvent{ID: "event", Timestamp: start.Add(time.Duration(index) * time.Second)}
	}
	snapshot := &timelineSnapshotStub{events: events}
	investigator := newTimelineInvestigator(t, map[View]store.CaseStore{view: snapshot})

	result, err := investigator.QueryTimeline(MultiHostTimelineOptions{
		Views: []View{view},
		Query: store.TimelineQueryOptions{
			Page: store.QueryPageOptions{Offset: 500, Limit: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 501 || len(result.Events) != 1 || result.Events[0].Event.Timestamp != events[500].Timestamp {
		t.Fatalf("large-offset result = %#v", result)
	}
	if len(snapshot.pageLimits) != 2 || snapshot.pageLimits[0] != maxInvestigationLimit || snapshot.pageLimits[1] != 1 {
		t.Fatalf("page limits = %#v, want [500 1]", snapshot.pageLimits)
	}
}

func TestInvestigatorTimelineReturnsNoPartialResultsOnError(t *testing.T) {
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-2", Version: "version-1"}
	backendError := errors.New("timeline unavailable")
	investigator := newTimelineInvestigator(t, map[View]store.CaseStore{
		view1: &timelineSnapshotStub{events: []model.TimelineEvent{{ID: "event-1"}}},
		view2: &timelineSnapshotStub{err: backendError},
	})

	result, err := investigator.QueryTimeline(MultiHostTimelineOptions{
		Views: []View{view1, view2},
		Query: store.TimelineQueryOptions{Page: store.QueryPageOptions{Limit: 1}},
	})
	if !errors.Is(err, backendError) {
		t.Fatalf("QueryTimeline() error = %v, want wrapped backend error", err)
	}
	if result.Total != 0 || len(result.Events) != 0 || len(result.ByView) != 0 {
		t.Fatalf("partial timeline escaped after error: %#v", result)
	}
}

func newTimelineInvestigator(t *testing.T, snapshots map[View]store.CaseStore) *Investigator {
	t.Helper()

	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]IngestRequest, 0, len(snapshots))
	for view, snapshot := range snapshots {
		requests = append(requests, IngestRequest{View: view, Snapshot: snapshot})
	}
	if _, err := repository.IngestBatch(requests...); err != nil {
		t.Fatal(err)
	}
	investigator, err := NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}

	return investigator
}
