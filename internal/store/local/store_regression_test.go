package local

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
)

func TestCaseStoreImplementsContract(t *testing.T) {
	var _ store.CaseStore = New(t.TempDir())
}

func TestQueryPaginationHelpers(t *testing.T) {
	tests := []struct {
		name       string
		offset     int
		limit      int
		total      int
		wantPage   QueryPage
		wantEnd    int
		wantResult store.QueryPageResult
	}{
		{
			name:       "defaults and clamps negative offset",
			offset:     -4,
			limit:      0,
			total:      150,
			wantPage:   QueryPage{Offset: 0, Limit: defaultQueryLimit},
			wantEnd:    100,
			wantResult: store.QueryPageResult{Offset: 0, Limit: defaultQueryLimit, HasMore: true},
		},
		{
			name:       "clamps offset and maximum limit",
			offset:     12,
			limit:      maxQueryLimit + 1,
			total:      5,
			wantPage:   QueryPage{Offset: 5, Limit: maxQueryLimit},
			wantEnd:    5,
			wantResult: store.QueryPageResult{Offset: 5, Limit: maxQueryLimit, HasMore: false},
		},
		{
			name:       "preserves requested page",
			offset:     2,
			limit:      2,
			total:      5,
			wantPage:   QueryPage{Offset: 2, Limit: 2},
			wantEnd:    4,
			wantResult: store.QueryPageResult{Offset: 2, Limit: 2, HasMore: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page := normalizeQueryPage(tt.offset, tt.limit, tt.total)
			if page != tt.wantPage {
				t.Fatalf("normalizeQueryPage() = %+v, want %+v", page, tt.wantPage)
			}

			end := queryPageEnd(page, tt.total)
			if end != tt.wantEnd {
				t.Fatalf("queryPageEnd() = %d, want %d", end, tt.wantEnd)
			}

			result := buildQueryPageResult(page, end, tt.total)
			if result != tt.wantResult {
				t.Fatalf("buildQueryPageResult() = %+v, want %+v", result, tt.wantResult)
			}
		})
	}
}

func TestNetworkEvidenceIdentityHelpers(t *testing.T) {
	connection := store.NetworkConnectionRecord{
		Protocol:      "tcp",
		LocalAddress:  "10.0.0.10",
		LocalPort:     49152,
		RemoteAddress: "203.0.113.7",
		RemotePort:    443,
		State:         "ESTABLISHED",
	}

	if got, want := networkConnectionKey(42, connection), "42|tcp|10.0.0.10|49152|203.0.113.7|443|ESTABLISHED"; got != want {
		t.Fatalf("networkConnectionKey() = %q, want %q", got, want)
	}

	item := localNetworkItemFromConnection(
		store.ProcessNetworkRecord{PID: 42},
		connection,
		"connection",
		true,
	)
	if want := "network:42:tcp:10.0.0.10:49152:203.0.113.7:443:connection"; item.ID != want {
		t.Fatalf("canonical network ID = %q, want %q", item.ID, want)
	}
}

func TestLocalCaseStoreBehaviorFixture(t *testing.T) {
	runCaseStoreBehaviorFixture(t, nil)
}

func TestCentralCaseStoreBehaviorFixture(t *testing.T) {
	runCaseStoreBehaviorFixture(
		t,
		func(t *testing.T, snapshot store.CaseStore) store.CaseStore {
			t.Helper()

			repository, err := centralstore.NewRepository()
			if err != nil {
				t.Fatal(err)
			}

			central, err := repository.Ingest(
				centralstore.IngestRequest{
					View: centralstore.View{
						CaseID:  "case-fixture",
						HostID:  "host-fixture",
						Version: "version-1",
					},
					Snapshot: snapshot,
				},
			)
			if err != nil {
				t.Fatal(err)
			}

			return central
		},
	)
}

func runCaseStoreBehaviorFixture(
	t *testing.T,
	wrap func(*testing.T, store.CaseStore) store.CaseStore,
) {
	t.Helper()

	caseDir := t.TempDir()
	t1 := time.Date(2026, time.January, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	t3 := t2.Add(24 * time.Hour)
	t4 := t3.Add(24 * time.Hour)

	writeFixtureJSON(t, caseDir, "files/files.json", model.FileTriageSnapshot{
		Files: []model.FileTriageItem{
			{Path: `C:\evidence\old-needle.exe`, Name: "old-needle.exe", ModifiedAt: t1},
			{Path: `C:\evidence\zero-needle.exe`, Name: "zero-needle.exe"},
			{Path: `C:\evidence\new-needle.exe`, Name: "new-needle.exe", ModifiedAt: t3},
		},
	})

	writeFixtureJSON(t, caseDir, "persistence/persistence.json", model.PersistenceSnapshot{
		Services: []model.ServiceInfo{
			{Name: "ZeroService", DisplayName: "Zero Service"},
		},
		RunKeys: []model.RegistryRunEntry{
			{Name: "FindingRun", Hive: "HKCU", Key: `Software\Microsoft\Windows\CurrentVersion\Run`, Command: "finding.exe", KeyModifiedAt: t1},
		},
		ScheduledTasks: []model.ScheduledTask{
			{Name: "RecentTask", Path: `\RecentTask`, ModifiedAt: t3},
		},
	})
	writeFixtureJSON(t, caseDir, "analysis/persistence_analysis.json", model.PersistenceAnalysis{
		Findings: []model.PersistenceFinding{
			{ID: "finding-1", Type: "run_key", Name: "FindingRun", Title: "Confirmed finding"},
		},
	})

	privateConnection := store.NetworkConnectionRecord{
		Protocol:      "tcp",
		Family:        "ipv4",
		LocalAddress:  "192.168.1.5",
		LocalPort:     50000,
		RemoteAddress: "10.0.0.2",
		RemotePort:    443,
		State:         "ESTABLISHED",
	}
	publicConnection := store.NetworkConnectionRecord{
		Protocol:      "tcp",
		Family:        "ipv4",
		LocalAddress:  "192.168.1.5",
		LocalPort:     50001,
		RemoteAddress: "8.8.8.8",
		RemotePort:    53,
		State:         "ESTABLISHED",
	}
	writeFixtureJSON(t, caseDir, "analysis/network_analysis.json", store.NetworkAnalysisRecord{
		Processes: []store.ProcessNetworkRecord{
			{
				PID:                 4242,
				ProcessName:         "needle.exe",
				Connections:         []store.NetworkConnectionRecord{privateConnection, publicConnection},
				ExternalConnections: []store.NetworkConnectionRecord{privateConnection},
			},
		},
	})

	writeFixtureJSON(t, caseDir, "timeline/timeline.json", model.Timeline{
		Events: []model.TimelineEvent{
			{ID: "timeline-process-new", Timestamp: t4, Category: "process", User: "alice", Description: "needle process new"},
			{ID: "timeline-login", Timestamp: t2, Category: "login", User: "alice", Description: "needle login"},
			{ID: "timeline-process-old", Timestamp: t1, Category: "process", User: "alice", Description: "needle process old"},
			{ID: "timeline-network-zero", Category: "network", User: "bob", Description: "needle network zero"},
		},
	})

	var s store.CaseStore = New(caseDir)
	if wrap != nil {
		s = wrap(t, s)
	}

	t.Run("files sort modified descending with zero last", func(t *testing.T) {
		result, err := s.QueryFiles(store.FileQueryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != 3 || len(result.Items) != 3 {
			t.Fatalf("QueryFiles totals = %d/%d, want 3/3", result.Total, len(result.Items))
		}
		want := []string{"new-needle.exe", "old-needle.exe", "zero-needle.exe"}
		for i, name := range want {
			if result.Items[i].Evidence.Name != name {
				t.Fatalf("QueryFiles item %d = %q, want %q", i, result.Items[i].Evidence.Name, name)
			}
		}
	})

	t.Run("persistence finding first then timestamp descending and zero last", func(t *testing.T) {
		result, err := s.QueryPersistence(store.PersistenceQueryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != 3 || len(result.Items) != 3 {
			t.Fatalf("QueryPersistence totals = %d/%d, want 3/3", result.Total, len(result.Items))
		}
		want := []string{"FindingRun", "RecentTask", "ZeroService"}
		for i, name := range want {
			if result.Items[i].Name != name {
				t.Fatalf("QueryPersistence item %d = %q, want %q", i, result.Items[i].Name, name)
			}
		}
		if result.Items[0].Finding == nil {
			t.Fatal("first persistence item has no finding")
		}
	})

	t.Run("timeline counts before pagination and without category filter", func(t *testing.T) {
		result, err := s.QueryTimeline(store.TimelineQueryOptions{
			Category: "process",
			User:     "alice",
			Order:    "desc",
			Page:     store.QueryPageOptions{Limit: 1},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != 2 || len(result.Events) != 1 || !result.Page.HasMore {
			t.Fatalf("QueryTimeline result = total %d, events %d, has_more %v", result.Total, len(result.Events), result.Page.HasMore)
		}
		if result.CategoryCounts["process"] != 2 || result.CategoryCounts["login"] != 1 {
			t.Fatalf("QueryTimeline category counts = %#v, want process=2 and login=1", result.CategoryCounts)
		}
		if _, ok := result.CategoryCounts["network"]; ok {
			t.Fatalf("QueryTimeline category counts unexpectedly include user-filtered network event: %#v", result.CategoryCounts)
		}
	})

	t.Run("network canonical ID and analyzer external membership", func(t *testing.T) {
		external := true
		result, err := s.QueryNetwork(store.NetworkQueryOptions{External: &external})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total != 1 || len(result.Items) != 1 {
			t.Fatalf("external QueryNetwork totals = %d/%d, want 1/1", result.Total, len(result.Items))
		}
		item := result.Items[0]
		if item.RemoteAddress != "10.0.0.2" {
			t.Fatalf("external item remote address = %q, want analyzer-selected 10.0.0.2", item.RemoteAddress)
		}
		if want := "network:4242:tcp:192.168.1.5:50000:10.0.0.2:443:connection"; item.ID != want {
			t.Fatalf("network item ID = %q, want %q", item.ID, want)
		}
	})

	t.Run("search totals and type counts before limit with global ordering", func(t *testing.T) {
		options := store.InvestigationSearchOptions{
			Query: "needle",
			Types: map[string]bool{"file": true, "timeline": true},
			Limit: 2,
		}
		limited, err := s.SearchInvestigation(options)
		if err != nil {
			t.Fatal(err)
		}
		if limited.Total != 7 || len(limited.Items) != 2 {
			t.Fatalf("limited search totals = %d/%d, want 7/2", limited.Total, len(limited.Items))
		}
		if limited.ByType["file"] != 3 || limited.ByType["timeline"] != 4 {
			t.Fatalf("limited search ByType = %#v, want file=3 and timeline=4", limited.ByType)
		}
		if limited.Items[0].ID != "timeline-process-new" || limited.Items[1].Title != "new-needle.exe" {
			t.Fatalf("limited search order = %#v", limited.Items)
		}

		options.Limit = 20
		full, err := s.SearchInvestigation(options)
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i < len(full.Items); i++ {
			previous := full.Items[i-1].Timestamp
			current := full.Items[i].Timestamp
			if previous.IsZero() && !current.IsZero() {
				t.Fatalf("non-zero timestamp follows zero timestamp at search index %d", i)
			}
			if !previous.IsZero() && !current.IsZero() && previous.Before(current) {
				t.Fatalf("search timestamps are not descending at index %d: %v before %v", i, previous, current)
			}
		}
		if !full.Items[len(full.Items)-1].Timestamp.IsZero() {
			t.Fatalf("last search timestamp = %v, want zero", full.Items[len(full.Items)-1].Timestamp)
		}
	})
}

func writeFixtureJSON(t *testing.T, root string, relativePath string, value any) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create fixture directory: %v", err)
	}

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture %s: %v", relativePath, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", relativePath, err)
	}
}
