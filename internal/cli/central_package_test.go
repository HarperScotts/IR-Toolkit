package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/packageio"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
	"ir-toolkit/internal/store/central"
)

var packageDomainFixtures = map[string]string{
	"process/processes.json":                 `[{"pid":42,"name":"HOST-needle.exe","path":"C:\\evidence\\needle.exe"}]`,
	"analysis/login_analysis.json":           `{"sessions":[{"logon_id":"0x000abc","user":"HOST-needle"}]}`,
	"files/files.json":                       `{"files":[{"path":"C:\\evidence\\needle.exe","name":"HOST-needle.exe"}]}`,
	"persistence/persistence.json":           `{"services":[{"name":"needle","display_name":"HOST-needle","binary_path":"C:\\evidence\\needle.exe"}]}`,
	"analysis/network_analysis.json":         `{"processes":[{"pid":42,"process_name":"HOST-needle.exe","connections":[{"protocol":"tcp","local_address":"192.168.1.5","local_port":50000,"remote_address":"10.0.0.2","remote_port":443,"state":"ESTABLISHED"}],"external_connections":[{"protocol":"tcp","local_address":"192.168.1.5","local_port":50000,"remote_address":"10.0.0.2","remote_port":443,"state":"ESTABLISHED"}]}]}`,
	"analysis/process_history_analysis.json": `{"processes":[{"id":"history:1","pid":42,"parent_pid":7,"process_name":"HOST-needle.exe","process_path":"C:\\evidence\\needle.exe","logon_id":"abc","matched_login":true,"current_process":true},{"id":"history:old","pid":42,"process_name":"old.exe","current_process":false}]}`,
	"analysis/powershell_analysis.json":      `{"script_blocks":[{"id":"powershell:1","process_id":42,"script_text":"HOST-needle","related_historical_process_id":"history:1"},{"id":"powershell:old","process_id":42,"script_text":"pid only","related_historical_process_id":"history:old"}]}`,
	"analysis/windows_event_analysis.json":   `{"activities":[{"id":"windows:1","process_id":42,"description":"HOST-needle","event_id":4688}]}`,
	"analysis/ioc_matches.json":              `{"matches":[{"ioc_type":"process","ioc_value":"HOST-needle.exe","pid":42,"object":"HOST-needle"}]}`,
	"timeline/timeline.json":                 `{"events":[{"id":"timeline:1","pid":42,"category":"process","description":"HOST-needle","related_ids":["history:1"]}]}`,
	"analysis/historical_correlation.json":   `{"nodes":[{"id":"node:1","type":"process","label":"HOST-needle"}],"edges":[{"id":"edge:1","from":"node:1","to":"node:2","type":"confirmed","basis":[{"type":"explicit","value":"HOST-needle"}]}]}`,
}

var packageDetailTargets = []struct{ kind, id string }{
	{"process", "process:42"}, {"login", "login:abc"}, {"file", `file:c:\evidence\needle.exe`},
	{"persistence", "persistence:service:needle:"}, {"network", "network:42:tcp:192.168.1.5:50000:10.0.0.2:443:connection"},
	{"historical_process", "history:1"}, {"powershell", "powershell:1"}, {"windows_event", "windows:1"},
	{"ioc", "ioc-match:0"}, {"timeline", "timeline:1"}, {"correlation_node", "node:1"}, {"correlation_edge", "edge:1"},
}

func writePackageDomainFixture(t *testing.T, host string) string {
	t.Helper()
	dir := writeCentralCaseFixture(t, host, "collection-1")
	for path, raw := range packageDomainFixtures {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(path)), []byte(strings.ReplaceAll(raw, "HOST", host)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data := []byte("原始证据\r\n")
	if err := os.Mkdir(filepath.Join(dir, "raw"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "raw/evidence.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	writeCentralJSON(t, dir, "manifest.json", model.Manifest{CaseID: "collection-1", Hostname: host, Files: []model.EvidenceFile{{Path: "raw/evidence.json", Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}}})
	return dir
}

func exportPackageTestFile(t *testing.T, source, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "case.ircase.tar")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = packageio.ExportCase(context.Background(), source, name, file, packageio.DefaultLimits())
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("export: %v %v", err, closeErr)
	}
	return path
}

func assertPackageTempEmpty(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary extraction retained: %v %v", entries, err)
	}
}

func TestPackageImportRestartAllTwelveDomains(t *testing.T) {
	dirs := []string{writePackageDomainFixture(t, "alpha"), writePackageDomainFixture(t, "beta")}
	_, before, loaded, err := buildCentralInvestigation("receiving-case", dirs)
	if err != nil {
		t.Fatal(err)
	}
	var packets []string
	originals := map[store.CaseView]map[string][]byte{}
	wantDetails := map[store.CaseView]map[string]store.ScopedEvidenceDetail{}
	for _, item := range loaded {
		originals[item.View] = readPackageTree(t, item.Dir)
		wantDetails[item.View] = map[string]store.ScopedEvidenceDetail{}
		for _, target := range packageDetailTargets {
			detail, found, err := before.EvidenceDetail(item.View, target.kind, target.id)
			if err != nil || !found {
				t.Fatalf("original %s: %v %v", target.kind, found, err)
			}
			wantDetails[item.View][target.kind] = detail
		}
		path := filepath.Join(t.TempDir(), "packed.tar")
		if _, err := packCaseFile(context.Background(), item.Dir, path); err != nil {
			t.Fatal(err)
		}
		if _, err := verifyCaseFile(context.Background(), path); err != nil {
			t.Fatal(err)
		}
		packets = append(packets, path)
	}
	repository := filepath.Join(t.TempDir(), "repository")
	parent := t.TempDir()
	for index, path := range packets {
		var output bytes.Buffer
		cmd := newCentralImportPackageCommand()
		cmd.SetOut(&output)
		cmd.SetArgs([]string{"--repository", repository, "--case-id", " receiving-case ", "--temp-parent", parent, path})
		if err := cmd.Execute(); err != nil {
			t.Fatal(err)
		}
		var receipt packageImportReceipt
		if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		if receipt.Status != "committed" || receipt.Committed == nil || !*receipt.Committed || receipt.View != loaded[index].View || receipt.CaseName != filepath.Base(dirs[index]) {
			t.Fatalf("receipt: %+v", receipt)
		}
		assertPackageTempEmpty(t, parent)
	}
	// Remove fixture evidence before opening fresh stores: restart must not rely
	// on cached objects, original paths or the now-cleaned extraction directories.
	for _, dir := range dirs {
		if err := os.Remove(filepath.Join(dir, "process/processes.json")); err != nil {
			t.Fatal(err)
		}
	}
	restarted, after, entries, err := openArchivedInvestigation(repository, "receiving-case")
	if err != nil || restarted.Len() != 2 {
		t.Fatalf("restart: %v", err)
	}
	for _, entry := range entries {
		if !reflect.DeepEqual(originals[entry.View], readPackageTree(t, entry.Dir)) {
			t.Fatal("archived raw bytes changed")
		}
		snapshot, _ := restarted.Open(entry.View)
		if _, found, err := snapshot.SecurityProviders(); err != nil || found {
			t.Fatalf("optional security-provider absence changed: %v %v", found, err)
		}
		if _, found, err := snapshot.Report(); err != nil || found {
			t.Fatalf("optional report absence changed: %v %v", found, err)
		}
		if snapshot.CaseName() != filepath.Base(dirs[map[string]int{"alpha": 0, "beta": 1}[entry.View.HostID]]) {
			t.Fatal("temporary basename replaced case name")
		}
		for _, target := range packageDetailTargets {
			detail, found, err := after.EvidenceDetail(entry.View, target.kind, target.id)
			if err != nil || !found || !reflect.DeepEqual(detail, wantDetails[entry.View][target.kind]) {
				t.Fatalf("restart detail %s host=%s: %v %v", target.kind, entry.View.HostID, found, err)
			}
		}
		history, err := snapshot.HistoricalProcessesByCurrentPID(42)
		if err != nil || len(history) != 1 || history[0].ID != "history:1" {
			t.Fatal("PID-only history inferred", err)
		}
		blocks, err := snapshot.PowerShellByHistoricalProcessID("history:1")
		if err != nil || len(blocks) != 1 || blocks[0].ID != "powershell:1" {
			t.Fatal("PowerShell link changed", err)
		}
	}
	views := []store.CaseView{loaded[0].View, loaded[1].View}
	for _, target := range packageDetailTargets {
		query := store.MultiHostSearchOptions{Views: views, Search: store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{target.kind: true}}}
		old, err := before.SearchInvestigation(query)
		if err != nil {
			t.Fatal(err)
		}
		current, err := after.SearchInvestigation(query)
		if err != nil || !reflect.DeepEqual(old, current) || len(current.Items) != 2 {
			t.Fatalf("search changed %s: %+v %v", target.kind, current, err)
		}
		for _, item := range current.Items {
			if item.Item.ID != target.id {
				t.Fatal("canonical/index ID changed")
			}
		}
	}
	oldTimeline, err := before.QueryTimeline(store.MultiHostTimelineOptions{Views: views})
	if err != nil {
		t.Fatal(err)
	}
	newTimeline, err := after.QueryTimeline(store.MultiHostTimelineOptions{Views: views})
	if err != nil || !reflect.DeepEqual(oldTimeline, newTimeline) {
		t.Fatal("zero-time timeline/counts changed", err)
	}
	if _, _, _, err := openArchivedInvestigation(repository, "collection-1"); err == nil {
		t.Fatal("package version selected the receiving investigation")
	}
}

func TestPackageImportFailureNoPublication(t *testing.T) {
	for _, kind := range []string{"bad domain", "missing domain", "bad tail", "writer busy", "duplicate", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			source := writeCentralCaseFixture(t, "alpha", "1")
			if kind == "bad domain" {
				if err := os.WriteFile(filepath.Join(source, "process/processes.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "missing domain" {
				if err := os.Remove(filepath.Join(source, "process/processes.json")); err != nil {
					t.Fatal(err)
				}
			}
			packet := exportPackageTestFile(t, source, "display / not-path")
			if kind == "bad tail" {
				file, err := os.OpenFile(packet, os.O_APPEND|os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.Write([]byte{1})
				closeErr := file.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			inputBefore, err := os.ReadFile(packet)
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			repository := filepath.Join(t.TempDir(), "repo")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var want error
			if kind == "writer busy" {
				if err := os.Mkdir(repository, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(repository, ".ingest.lock"), []byte("keep-lock"), 0600); err != nil {
					t.Fatal(err)
				}
				want = archive.ErrWriterBusy
			}
			if kind == "duplicate" {
				if _, err := importPackageFile(ctx, packet, repository, "received", parent); err != nil {
					t.Fatal(err)
				}
				want = central.ErrDuplicateView
			}
			if kind == "cancel" {
				cancel()
				want = context.Canceled
			}
			result, err := importPackageFile(ctx, packet, repository, "received", parent)
			if err == nil || (want != nil && !errors.Is(err, want)) || (result.Committed != nil && *result.Committed) {
				t.Fatalf("failure: %+v %v", result, err)
			}
			if kind == "writer busy" || kind == "duplicate" {
				encoded, encodeErr := json.Marshal(result)
				if encodeErr != nil || result.Status != "commit-outcome-unknown" || result.Committed != nil || !bytes.Contains(encoded, []byte(`"committed":null`)) {
					t.Fatalf("commit error falsely reports uncommitted: %s %v", encoded, encodeErr)
				}
			}
			assertPackageTempEmpty(t, parent)
			inputAfter, readErr := os.ReadFile(packet)
			if readErr != nil || !bytes.Equal(inputBefore, inputAfter) {
				t.Fatal("input package changed")
			}
			if kind == "writer busy" {
				lock, err := os.ReadFile(filepath.Join(repository, ".ingest.lock"))
				if err != nil || string(lock) != "keep-lock" {
					t.Fatal("foreign lock removed")
				}
			}
			if kind == "duplicate" || kind == "writer busy" {
				repo, _, err := archive.Load(repository, loadArchivedSnapshot)
				expected := 0
				if kind == "duplicate" {
					expected = 1
				}
				if err != nil || repo.Len() != expected {
					t.Fatalf("failed import published: %v", err)
				}
			} else if _, err := os.Stat(repository); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight created repository: %v", err)
			}
		})
	}
}

func TestPackageImportDisplayNameAndReceiptFailure(t *testing.T) {
	source := writeCentralCaseFixture(t, "alpha", "1")
	packet := exportPackageTestFile(t, source, "display / name")
	parent := t.TempDir()
	repository := filepath.Join(t.TempDir(), "repo")
	cmd := newCentralImportPackageCommand()
	cmd.SetOut(packageReceiptFailureWriter{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--repository", repository, "--case-id", "received", "--temp-parent", parent, packet})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), `outcome "committed"`) {
		t.Fatalf("reporting failure: %v", err)
	}
	repo, _, err := archive.Load(repository, loadArchivedSnapshot)
	if err != nil || repo.Len() != 1 {
		t.Fatal("reporting failure lost commit", err)
	}
	snapshot, found := repo.Open(store.CaseView{CaseID: "received", HostID: "alpha", Version: "1"})
	if !found || snapshot.CaseName() != "display / name" {
		t.Fatal("explicit display name not preserved")
	}
	assertPackageTempEmpty(t, parent)
}

func TestPackageImportArgumentsAndExtractionRepositoryGuard(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"central-import-package"})
	if err != nil || cmd.Name() != "central-import-package" {
		t.Fatal("command not registered")
	}
	for _, args := range [][]string{nil, {"package.tar"}, {"--repository", "repo", "--case-id", "id", "package.tar"}} {
		cmd := newCentralImportPackageCommand()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatal("missing args/flags accepted")
		}
	}
	root := t.TempDir()
	for _, path := range []string{root, filepath.Join(root, "case/repo"), filepath.Join(root, "sibling/repo")} {
		if err := rejectRepositoryInsideExtraction(path, root); err == nil {
			t.Fatal("repository inside temporary root accepted")
		}
	}
	if err := rejectRepositoryInsideExtraction(filepath.Join(t.TempDir(), "new/repo"), root); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "extraction-alias")
	if err := os.Symlink(root, alias); err == nil {
		if err := rejectRepositoryInsideExtraction(filepath.Join(alias, "new/repo"), root); err == nil {
			t.Fatal("parent alias bypassed extraction-root guard")
		}
	}
}
