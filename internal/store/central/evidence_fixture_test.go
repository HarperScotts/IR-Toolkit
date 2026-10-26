package central_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/central"
	"ir-toolkit/internal/store/local"
)

// Raw snake_case JSON deliberately exercises the Analyzer/Store boundary,
// instead of marshaling the same Go types that the loader will unmarshal.
var detailFixtureFiles = map[string]string{
	"process/processes.json":                 `[{"pid":42,"name":"HOST-needle.exe","path":"C:\\evidence\\needle.exe"}]`,
	"analysis/login_analysis.json":           `{"sessions":[{"logon_id":"0x000abc","user":"HOST-needle"}]}`,
	"files/files.json":                       `{"files":[{"path":"C:\\evidence\\needle.exe","name":"HOST-needle.exe"}]}`,
	"persistence/persistence.json":           `{"services":[{"name":"needle","display_name":"HOST-needle","binary_path":"C:\\evidence\\needle.exe"}]}`,
	"analysis/network_analysis.json":         `{"processes":[{"pid":42,"process_name":"HOST-needle.exe","connections":[{"protocol":"tcp","local_address":"192.168.1.5","local_port":50000,"remote_address":"10.0.0.2","remote_port":443,"state":"ESTABLISHED"}],"external_connections":[{"protocol":"tcp","local_address":"192.168.1.5","local_port":50000,"remote_address":"10.0.0.2","remote_port":443,"state":"ESTABLISHED"}]}]}`,
	"analysis/process_history_analysis.json": `{"processes":[{"id":"history:1","pid":42,"parent_pid":7,"process_name":"HOST-needle.exe","process_path":"C:\\evidence\\needle.exe","command_line":"HOST-needle --run","parent_process_name":"parent.exe","logon_id":"abc","token_elevation_type":"full","mandatory_label":"high","matched_login":true,"current_process":true,"current_process_path":"C:\\evidence\\needle.exe"},{"id":"history:old","pid":42,"process_name":"old.exe","current_process":false}]}`,
	"analysis/powershell_analysis.json":      `{"script_blocks":[{"id":"powershell:1","process_id":42,"script_text":"HOST-needle","related_historical_process_id":"history:1"},{"id":"powershell:old","process_id":42,"script_text":"pid only","related_historical_process_id":"history:old"}]}`,
	"analysis/windows_event_analysis.json":   `{"activities":[{"id":"windows:1","process_id":42,"description":"HOST-needle","event_id":4688}]}`,
	"analysis/ioc_matches.json":              `{"matches":[{"ioc_type":"process","ioc_value":"HOST-needle.exe","pid":42,"object":"HOST-needle"}]}`,
	"timeline/timeline.json":                 `{"events":[{"id":"timeline:1","pid":42,"category":"process","description":"HOST-needle","related_ids":["history:1"]}]}`,
	"analysis/historical_correlation.json":   `{"nodes":[{"id":"node:1","type":"process","label":"HOST-needle"}],"edges":[{"id":"edge:1","from":"node:1","to":"node:2","type":"confirmed","basis":[{"type":"explicit","value":"HOST-needle"}]}]}`,
}

var detailFixtureCases = []struct {
	typeName string
	id       string
	path     string
}{
	{"process", "process:42", "process/processes.json"},
	{"login", "login:abc", "analysis/login_analysis.json"},
	{"file", `file:c:\evidence\needle.exe`, "files/files.json"},
	{"persistence", "persistence:service:needle:", "persistence/persistence.json"},
	{"network", "network:42:tcp:192.168.1.5:50000:10.0.0.2:443:connection", "analysis/network_analysis.json"},
	{"historical_process", "history:1", "analysis/process_history_analysis.json"},
	{"powershell", "powershell:1", "analysis/powershell_analysis.json"},
	{"windows_event", "windows:1", "analysis/windows_event_analysis.json"},
	{"ioc", "ioc-match:0", "analysis/ioc_matches.json"},
	{"timeline", "timeline:1", "timeline/timeline.json"},
	{"correlation_node", "node:1", "analysis/historical_correlation.json"},
	{"correlation_edge", "edge:1", "analysis/historical_correlation.json"},
}

func writeDetailFixture(t *testing.T, root, relativePath, raw string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func publishDetailFixture(t *testing.T, view store.CaseView, snapshot store.CaseStore) *central.Investigator {
	t.Helper()
	repository, err := central.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Ingest(central.IngestRequest{View: view, Snapshot: snapshot}); err != nil {
		t.Fatal(err)
	}
	investigator, err := central.NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}
	return investigator
}

func TestScopedEvidenceJSONFixtureAllDomains(t *testing.T) {
	repository, err := central.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	views := []store.CaseView{{CaseID: "case", HostID: "alpha", Version: "1"}, {CaseID: "case", HostID: "beta", Version: "1"}}
	for _, view := range views {
		root := t.TempDir()
		for path, raw := range detailFixtureFiles {
			writeDetailFixture(t, root, path, strings.ReplaceAll(raw, "HOST", view.HostID))
		}
		if _, err := repository.Ingest(central.IngestRequest{View: view, Snapshot: local.New(root)}); err != nil {
			t.Fatal(err)
		}
	}
	investigator, err := central.NewInvestigator(repository)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range detailFixtureCases {
		t.Run(tt.typeName, func(t *testing.T) {
			for _, view := range views {
				result, found, err := investigator.EvidenceDetail(view, tt.typeName, tt.id)
				if err != nil || !found {
					t.Fatalf("%s lookup found=%v err=%v", view.HostID, found, err)
				}
				if result.View != view || result.Type != tt.typeName || result.ID != tt.id {
					t.Fatalf("wrong identity: %#v", result)
				}
				data, err := json.Marshal(result.Evidence)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(data), view.HostID+"-needle") {
					t.Fatalf("wrong host evidence: %s", data)
				}
			}
			search, err := investigator.SearchInvestigation(store.MultiHostSearchOptions{Views: views, Search: store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{tt.typeName: true}}})
			if err != nil {
				t.Fatal(err)
			}
			if len(search.Items) != 2 {
				t.Fatalf("search items=%d, want one per host", len(search.Items))
			}
			for _, item := range search.Items {
				if item.Item.ID != tt.id {
					t.Fatalf("Search ID=%q, lookup ID=%q", item.Item.ID, tt.id)
				}
				if _, found, err := investigator.EvidenceDetail(item.View, item.Item.Type, item.Item.ID); err != nil || !found {
					t.Fatalf("search-to-detail found=%v err=%v", found, err)
				}
			}
			missingID := tt.id + ":missing"
			switch tt.typeName {
			case "process":
				missingID = "process:43"
			case "login":
				missingID = "login:def"
			case "ioc":
				missingID = "ioc-match:1"
			}
			result, found, err := investigator.EvidenceDetail(views[0], tt.typeName, missingID)
			if err != nil || found || result.Evidence != nil {
				t.Fatalf("missing record differs from read error: found=%v err=%v result=%#v", found, err, result)
			}
		})
	}
	result, _, err := investigator.EvidenceDetail(views[0], "historical_process", "history:1")
	if err != nil {
		t.Fatal(err)
	}
	history := result.Evidence.(store.HistoricalProcessRecord)
	if history.ParentPID != 7 || history.CommandLine != "alpha-needle --run" || history.ParentProcessName != "parent.exe" || history.LogonID != "abc" || history.TokenElevationType != "full" || history.MandatoryLabel != "high" || !history.MatchedLogin || !history.CurrentProcess || history.CurrentProcessPath == "" {
		t.Fatalf("snake_case data lost: %#v", history)
	}
	result, _, err = investigator.EvidenceDetail(views[0], "network", detailFixtureCases[4].id)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Evidence.(store.NetworkQueryItem).External {
		t.Fatal("Analyzer-selected private IP lost External membership")
	}
	result, _, err = investigator.EvidenceDetail(views[0], "correlation_edge", "edge:1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Evidence.(store.CorrelationEdgeRecord).Basis[0].Value != "alpha-needle" {
		t.Fatal("explicit correlation basis lost")
	}
	if _, found, err := investigator.EvidenceDetail(views[0], "file", `file:c:\evidence\needle.exe.bak`); err != nil || found {
		t.Fatalf("similar path falsely matched: %v, %v", found, err)
	}
	primary, _ := repository.Open(views[0])
	confirmed, err := primary.HistoricalProcessesByCurrentPID(42)
	if err != nil || len(confirmed) != 1 || confirmed[0].ID != "history:1" {
		t.Fatalf("PID-only history inferred: %#v %v", confirmed, err)
	}
	blocks, err := primary.PowerShellByHistoricalProcessID(confirmed[0].ID)
	if err != nil || len(blocks) != 1 || blocks[0].ID != "powershell:1" {
		t.Fatalf("PID-only PowerShell inferred: %#v %v", blocks, err)
	}
	var _ model.CorrelationEvidence // The domain evidence type remains separate from Store records.
}

func TestScopedEvidenceJSONReadFailuresRemainErrors(t *testing.T) {
	view := store.CaseView{CaseID: "case", HostID: "alpha", Version: "1"}
	for _, tt := range detailFixtureCases {
		t.Run(tt.typeName, func(t *testing.T) {
			root := t.TempDir()
			missing := publishDetailFixture(t, view, local.New(root))
			result, found, err := missing.EvidenceDetail(view, tt.typeName, tt.id)
			if !errors.Is(err, os.ErrNotExist) || found || result.Evidence != nil {
				t.Fatalf("missing file hidden: found=%v err=%v result=%#v", found, err, result)
			}
			writeDetailFixture(t, root, tt.path, "{")
			malformed := publishDetailFixture(t, view, local.New(root))
			result, found, err = malformed.EvidenceDetail(view, tt.typeName, tt.id)
			var syntax *json.SyntaxError
			if !errors.As(err, &syntax) || found || result.Evidence != nil {
				t.Fatalf("decode error hidden: found=%v err=%v result=%#v", found, err, result)
			}
		})
	}
}
