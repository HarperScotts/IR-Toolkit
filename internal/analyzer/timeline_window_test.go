package analyzer

import (
	"reflect"
	"testing"
	"time"

	"ir-toolkit/internal/model"
)

func TestTimelineWindowPreservesContextAndEvidence(t *testing.T) {
	since := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	until := since.Add(time.Hour)
	input := model.Timeline{Events: []model.TimelineEvent{
		{ID: "before", Timestamp: since.Add(-time.Nanosecond), Category: "login"},
		{ID: "since", Timestamp: since, Category: "login", RelatedIDs: []string{"login:abc"}, Metadata: map[string]string{"raw": "unchanged"}},
		{ID: "until", Timestamp: until, Category: "process_history"},
		{ID: "after", Timestamp: until.Add(time.Nanosecond), Category: "powershell"},
		{ID: "network-context", Category: "network"},
		{ID: "persistence-context", Category: "persistence"},
	}}
	buildTimelineStatistics(&input)
	want := []model.TimelineEvent{input.Events[1], input.Events[2], input.Events[4], input.Events[5]}
	filtered := FilterTimelineByWindow(input, &since, &until)
	if !reflect.DeepEqual(filtered.Events, want) {
		t.Fatalf("scope/order/evidence changed: %+v", filtered.Events)
	}
	if filtered.Statistics.EventCount != 4 || filtered.Statistics.LoginEvents != 1 || filtered.Statistics.HistoricalProcessEvents != 1 || filtered.Statistics.NetworkEvents != 1 || filtered.Statistics.PersistenceEvents != 1 || filtered.Statistics.PowerShellEvents != 0 {
		t.Fatalf("filtered statistics stale: %+v", filtered.Statistics)
	}
	if input.Statistics.EventCount != 6 || len(input.Events) != 6 || input.Events[0].ID != "before" || input.Events[3].ID != "after" {
		t.Fatal("filter mutated input")
	}
	if !reflect.DeepEqual(FilterTimelineByWindow(input, nil, nil), input) {
		t.Fatal("unbounded timeline changed")
	}
}
