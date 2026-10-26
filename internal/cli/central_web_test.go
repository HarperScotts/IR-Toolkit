package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
	webserver "ir-toolkit/internal/web"
)

// Opt-in local server for manually exercising the embedded UI with synthetic
// evidence. No collected host data is used or modified.
func TestCentralBrowserFixture(t *testing.T) {
	address := os.Getenv("IR_TOOLKIT_BROWSER_TEST_ADDR")
	if address == "" {
		t.Skip("set IR_TOOLKIT_BROWSER_TEST_ADDR to serve the browser fixture")
	}
	cases := writeCentralBrowserCases(t)
	first := cases[0]
	repository, investigator, loaded, err := buildCentralInvestigation("fixture-investigation", cases)
	if err != nil {
		t.Fatal(err)
	}
	primary, _ := repository.Open(loaded[0].View)
	server, err := webserver.NewServer(webserver.Options{CaseDir: first, Store: primary, MultiHostStore: investigator, ListenAddr: address})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	t.Logf("Synthetic browser fixture: http://%s", address)
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

// Prepare an opt-in archive, then exit normally so t.TempDir removes all source
// cases. Run the real central-web command against this archive across restarts.
// Use only a newly created empty destination dedicated to this fixture.
func TestPrepareArchivedBrowserFixture(t *testing.T) {
	root := os.Getenv("IR_TOOLKIT_ARCHIVE_BROWSER_ROOT")
	if root == "" {
		t.Skip("set IR_TOOLKIT_ARCHIVE_BROWSER_ROOT to prepare a synthetic archive")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("browser fixture archive destination must be empty")
	}
	oldRepository, oldCaseID := importRepository, importCaseID
	t.Cleanup(func() { importRepository, importCaseID = oldRepository, oldCaseID })
	importRepository, importCaseID = root, "fixture-investigation"
	cases := writeCentralBrowserCases(t)
	if err := centralImportCmd.RunE(&cobra.Command{}, cases); err != nil {
		t.Fatal(err)
	}
	for _, source := range cases {
		t.Logf("Temporary source (removed at test exit): %s", source)
	}
	t.Logf("Prepared synthetic archive: %s", root)
}

func writeCentralBrowserCases(t *testing.T) []string {
	t.Helper()
	first := writeCentralCaseFixture(t, "fixture-alpha", "collection-1")
	second := writeCentralCaseFixture(t, "fixture-beta", "collection-2")
	for _, dir := range []string{first, second} {
		writeCentralJSON(t, dir, "process/processes.json", []model.Process{{PID: 42, Name: "needle.exe"}})
		events := make([]model.TimelineEvent, 52)
		for index := range events {
			events[index] = model.TimelineEvent{
				ID:        fmt.Sprintf("event:%d", index),
				Timestamp: time.Date(2026, 1, 1, 0, index, 0, 0, time.UTC),
				Category:  "process", Description: "needle process event", PID: 42,
			}
		}
		events[0].Timestamp = time.Time{}
		writeCentralJSON(t, dir, "timeline/timeline.json", model.Timeline{Events: events})
	}
	return []string{first, second}
}

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
