package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
)

func TestBuildCentralInvestigationLoadsMultipleFrozenViews(t *testing.T) {
	case1 := writeCentralCaseFixture(t, "host-1", "collection-1")
	case2 := writeCentralCaseFixture(t, "host-2", "collection-2")

	repository, investigator, loaded, err := buildCentralInvestigation(
		"investigation-1",
		[]string{case1, case2},
	)
	if err != nil {
		t.Fatal(err)
	}
	if repository.Len() != 2 || len(loaded) != 2 {
		t.Fatalf("repository/loaded lengths = %d/%d, want 2/2", repository.Len(), len(loaded))
	}
	view1 := store.CaseView{CaseID: "investigation-1", HostID: "host-1", Version: "collection-1"}
	if loaded[0].View != view1 {
		t.Fatalf("first view = %+v, want %+v", loaded[0].View, view1)
	}
	primary, ok := repository.Open(view1)
	if !ok {
		t.Fatal("primary view was not published")
	}

	writeCentralJSON(t, case1, "timeline/timeline.json", model.Timeline{
		Events: []model.TimelineEvent{{ID: "late-disk-change", Description: "must not appear"}},
	})
	timeline, err := primary.QueryTimeline(store.TimelineQueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if timeline.Total != 0 || len(timeline.Events) != 0 {
		t.Fatalf("frozen view observed later disk change: %#v", timeline)
	}

	search, err := investigator.SearchInvestigation(store.MultiHostSearchOptions{
		Views:  []store.CaseView{loaded[0].View, loaded[1].View},
		Search: store.InvestigationSearchOptions{Query: "needle"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if search.Total != 0 || len(search.Items) != 0 || len(search.ByView) != 2 {
		t.Fatalf("empty multi-host search = %#v", search)
	}
}

func TestBuildCentralInvestigationRejectsDuplicateView(t *testing.T) {
	caseDir := writeCentralCaseFixture(t, "host-1", "collection-1")

	_, _, _, err := buildCentralInvestigation(
		"investigation-1",
		[]string{caseDir, caseDir},
	)
	if !errors.Is(err, centralstore.ErrDuplicateView) {
		t.Fatalf("buildCentralInvestigation() error = %v, want %v", err, centralstore.ErrDuplicateView)
	}
}

func TestLoadCentralViewRequiresEvidenceBackedIdentity(t *testing.T) {
	caseDir := writeCentralCaseFixture(t, "", "collection-1")

	_, err := loadCentralView("investigation-1", caseDir)
	if !errors.Is(err, store.ErrInvalidCaseView) {
		t.Fatalf("loadCentralView() error = %v, want %v", err, store.ErrInvalidCaseView)
	}
}

func writeCentralCaseFixture(t *testing.T, hostname string, version string) string {
	t.Helper()

	caseDir := t.TempDir()
	writeCentralJSON(t, caseDir, "manifest.json", model.Manifest{CaseID: version, Hostname: hostname})
	writeCentralJSON(t, caseDir, "host/host.json", model.HostInfo{Hostname: hostname})
	writeCentralJSON(t, caseDir, "capabilities/capabilities.json", model.AuditCapabilitySnapshot{})
	writeCentralJSON(t, caseDir, "files/files.json", model.FileTriageSnapshot{})
	writeCentralJSON(t, caseDir, "persistence/persistence.json", model.PersistenceSnapshot{})
	writeCentralJSON(t, caseDir, "process/processes.json", []model.Process{})
	writeCentralJSON(t, caseDir, "analysis/login_analysis.json", model.LoginAnalysis{})
	writeCentralJSON(t, caseDir, "analysis/network_analysis.json", store.NetworkAnalysisRecord{})
	writeCentralJSON(t, caseDir, "timeline/timeline.json", model.Timeline{})
	writeCentralJSON(t, caseDir, "analysis/process_history_analysis.json", store.ProcessHistoryRecord{})
	writeCentralJSON(t, caseDir, "analysis/powershell_analysis.json", model.PowerShellAnalysis{})
	writeCentralJSON(t, caseDir, "analysis/windows_event_analysis.json", model.WindowsEventAnalysis{})
	writeCentralJSON(t, caseDir, "analysis/ioc_matches.json", model.IOCScanResult{})
	writeCentralJSON(t, caseDir, "analysis/historical_correlation.json", store.HistoricalCorrelationRecord{})

	return caseDir
}

func writeCentralJSON(t *testing.T, root string, relativePath string, value any) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
