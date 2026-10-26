package local

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ir-toolkit/internal/store"
)

var searchDomainPaths = map[string]string{
	"process": "process/processes.json", "login": "analysis/login_analysis.json",
	"network": "analysis/network_analysis.json", "historical_process": "analysis/process_history_analysis.json",
	"powershell": "analysis/powershell_analysis.json", "windows_event": "analysis/windows_event_analysis.json",
	"ioc": "analysis/ioc_matches.json", "file": "files/files.json", "persistence": "persistence/persistence.json",
	"timeline": "timeline/timeline.json", "correlation_node": "analysis/historical_correlation.json",
	"correlation_edge": "analysis/historical_correlation.json",
}

func writeSearchDomains(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for kind, relative := range searchDomainPaths {
		var value any = map[string]any{}
		if kind == "process" {
			value = []map[string]any{{"pid": 42, "name": "needle.exe"}}
		}
		writeFixtureJSON(t, root, relative, value)
	}
	return root
}

func assertFailedSearchEmpty(t *testing.T, result store.InvestigationSearchStoreResult) {
	t.Helper()
	if result.Total != 0 || len(result.Items) != 0 || len(result.ByType) != 0 {
		t.Fatalf("failed search leaked partial results: %+v", result)
	}
}

func TestSearchPropagatesSelectedDomainErrors(t *testing.T) {
	for kind, relative := range searchDomainPaths {
		for _, failure := range []string{"missing", "malformed", "directory"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				root := writeSearchDomains(t)
				path := filepath.Join(root, filepath.FromSlash(relative))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch failure {
				case "malformed":
					if err := os.WriteFile(path, []byte(`{"broken":`), 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				}
				snapshot := New(root)
				for attempt := range 2 {
					result, err := snapshot.SearchInvestigation(store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{kind: true}, Limit: 1})
					if err == nil || !strings.Contains(err.Error(), relative[strings.LastIndex(relative, "/")+1:]) {
						t.Fatalf("attempt %d: missing contextual error: %v", attempt, err)
					}
					if failure == "missing" && !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("lost missing-file identity: %v", err)
					}
					var syntax *json.SyntaxError
					if failure == "malformed" && !errors.As(err, &syntax) {
						t.Fatalf("lost JSON error identity: %v", err)
					}
					assertFailedSearchEmpty(t, result)
				}
				// A later failing domain must invalidate an all-domain search,
				// even when the process domain has matching evidence.
				result, err := New(root).SearchInvestigation(store.InvestigationSearchOptions{Query: "needle", Limit: 1})
				if err == nil {
					t.Fatal("all-domain search hid failure")
				}
				assertFailedSearchEmpty(t, result)
			})
		}
	}
}

func TestSearchOnlyLoadsSelectedDomains(t *testing.T) {
	root := t.TempDir()
	writeFixtureJSON(t, root, searchDomainPaths["process"], []map[string]any{{"pid": 42, "name": "needle.exe"}})
	result, err := New(root).SearchInvestigation(store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{"process": true, "timeline": false}})
	if err != nil || result.Total != 1 || result.ByType["process"] != 1 || len(result.Items) != 1 {
		t.Fatalf("selected search: %+v, %v", result, err)
	}
	for _, options := range []store.InvestigationSearchOptions{
		{Query: "  "}, {Query: "needle", Types: map[string]bool{"unknown": true}}, {Query: "needle", Types: map[string]bool{"process": false}},
	} {
		result, err := New(t.TempDir()).SearchInvestigation(options)
		if err != nil {
			t.Fatalf("no selected work: %v", err)
		}
		assertFailedSearchEmpty(t, result)
	}
	result, err = New(root).SearchInvestigation(store.InvestigationSearchOptions{Query: "absent", Types: map[string]bool{"process": true}})
	if err != nil {
		t.Fatal("normal no-match is not an error", err)
	}
	assertFailedSearchEmpty(t, result)
}

func TestSearchOptionalAnalysisAbsenceRemainsAllowed(t *testing.T) {
	for _, item := range []struct{ kind, optional string }{
		{"file", "analysis/file_analysis.json"}, {"persistence", "analysis/persistence_analysis.json"},
	} {
		t.Run(item.kind, func(t *testing.T) {
			root := writeSearchDomains(t)
			options := store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{item.kind: true}}
			if _, err := New(root).SearchInvestigation(options); err != nil {
				t.Fatal("optional absence rejected", err)
			}
			path := filepath.Join(root, filepath.FromSlash(item.optional))
			if err := os.WriteFile(path, []byte(`{"broken":`), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := New(root).SearchInvestigation(options)
			var syntax *json.SyntaxError
			if !errors.As(err, &syntax) {
				t.Fatalf("optional corrupt file hidden: %v", err)
			}
			assertFailedSearchEmpty(t, result)
		})
	}
}
