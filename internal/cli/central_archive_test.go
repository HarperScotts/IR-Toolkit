package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/cobra"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
	"ir-toolkit/internal/store/central"
)

func TestCentralArchiveCommandAndReadOnlyArguments(t *testing.T) {
	oldRepository, oldCaseID, oldWebRepository := importRepository, importCaseID, centralWebRepository
	t.Cleanup(func() {
		importRepository, importCaseID, centralWebRepository = oldRepository, oldCaseID, oldWebRepository
	})
	source := archiveFixtureSource(t, "alpha", "1")
	importRepository, importCaseID = t.TempDir(), source.View.CaseID
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	if err := centralImportCmd.RunE(cmd, []string{source.Dir}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("Committed 1 views")) {
		t.Fatalf("command output: %s", output.String())
	}
	repository, _, _, err := openArchivedInvestigation(importRepository, importCaseID)
	if err != nil || repository.Len() != 1 {
		t.Fatalf("command did not create recoverable snapshot: %v", err)
	}
	centralWebRepository = importRepository
	if err := centralWebCmd.Args(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if err := centralWebCmd.Args(cmd, []string{source.Dir}); err == nil {
		t.Fatal("read-only repository mode also accepted source directories")
	}
	centralWebRepository = ""
	if err := centralWebCmd.Args(cmd, nil); err == nil {
		t.Fatal("directory mode accepted no source")
	}
	if err := centralWebCmd.Args(cmd, []string{source.Dir}); err != nil {
		t.Fatal(err)
	}
}

func archiveFixtureSource(t *testing.T, host, version string) archive.Source {
	t.Helper()
	dir := writeCentralCaseFixture(t, host, version)
	writeCentralJSON(t, dir, "process/processes.json", []model.Process{{PID: 42, Name: host + "-needle.exe"}})
	writeCentralJSON(t, dir, "timeline/timeline.json", model.Timeline{Events: []model.TimelineEvent{{ID: "event:0", PID: 42, Category: "process", Description: host + " needle"}}})
	return archive.Source{View: store.CaseView{CaseID: "investigation", HostID: host, Version: version}, Dir: dir}
}

func TestArchiveRestartOwnsEvidenceAndScopesInvestigation(t *testing.T) {
	root := t.TempDir()
	sources := []archive.Source{archiveFixtureSource(t, "alpha", "1"), archiveFixtureSource(t, "beta", "1")}
	if err := archive.Commit(root, sources, loadArchivedSnapshot); err != nil {
		t.Fatal(err)
	}
	before, entries, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil || before.Len() != 2 || len(entries) != 2 {
		t.Fatalf("Load = %v, %v", before, err)
	}
	original, _ := os.ReadFile(filepath.Join(sources[0].Dir, "process", "processes.json"))
	copied, _ := os.ReadFile(filepath.Join(entries[0].Dir, "process", "processes.json"))
	if !bytes.Equal(original, copied) {
		t.Fatal("raw evidence bytes changed")
	}
	first, _ := before.Open(sources[0].View)
	if first.CaseName() != filepath.Base(sources[0].Dir) {
		t.Fatal("CaseName changed during archive")
	}
	writeCentralJSON(t, sources[0].Dir, "process/processes.json", []model.Process{{PID: 42, Name: "changed"}})
	if err := os.Remove(filepath.Join(sources[1].Dir, "process", "processes.json")); err != nil {
		t.Fatal(err)
	}
	// A new Load creates new Store instances: this is restart recovery, not a
	// query against previously cached data.
	repository, investigator, loaded, err := openArchivedInvestigation(root, "investigation")
	if err != nil || repository.Len() != 2 || len(loaded) != 2 {
		t.Fatalf("restart: %v", err)
	}
	result, err := investigator.SearchInvestigation(store.MultiHostSearchOptions{Views: []store.CaseView{sources[0].View, sources[1].View}, Search: store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{"process": true}}})
	if err != nil || result.Total != 2 {
		t.Fatalf("restart search: %+v, %v", result, err)
	}
	detail, found, err := investigator.EvidenceDetail(sources[1].View, "process", "process:42")
	if err != nil || !found || detail.Evidence.(model.Process).Name != "beta-needle.exe" {
		t.Fatalf("restart detail: %+v, %v", detail, err)
	}
	other := archiveFixtureSource(t, "gamma", "1")
	other.View.CaseID = "other-investigation"
	if err := archive.Commit(root, []archive.Source{other}, loadArchivedSnapshot); err != nil {
		t.Fatal(err)
	}
	selected, _, selectedViews, err := openArchivedInvestigation(root, "investigation")
	if err != nil || selected.Len() != 2 || len(selectedViews) != 2 {
		t.Fatalf("case scope: %v", err)
	}
	if _, _, _, err := openArchivedInvestigation(root, "missing"); err == nil {
		t.Fatal("missing case silently broadened scope")
	}
}

func TestArchiveFailureDoesNotPublishPartialBatch(t *testing.T) {
	root := t.TempDir()
	good := archiveFixtureSource(t, "alpha", "1")
	bad := archiveFixtureSource(t, "beta", "1")
	if err := os.WriteFile(filepath.Join(bad.Dir, "process", "processes.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := archive.Commit(root, []archive.Source{good, bad}, loadArchivedSnapshot); err == nil {
		t.Fatal("invalid second case committed")
	}
	repository, _, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil || repository.Len() != 0 {
		t.Fatalf("partial batch exposed: %v", err)
	}
	files, _ := os.ReadDir(root)
	if len(files) != 0 {
		t.Fatal("failed invocation left its stage/lock behind")
	}
	if err := archive.Commit(root, []archive.Source{good}, loadArchivedSnapshot); err != nil {
		t.Fatal(err)
	}
	if err := archive.Commit(root, []archive.Source{good}, loadArchivedSnapshot); !errors.Is(err, central.ErrDuplicateView) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := archive.Commit(root, []archive.Source{bad, bad}, loadArchivedSnapshot); !errors.Is(err, central.ErrDuplicateView) {
		t.Fatalf("batch duplicate: %v", err)
	}
	repository, _, err = archive.Load(root, loadArchivedSnapshot)
	if err != nil || repository.Len() != 1 {
		t.Fatal("duplicate modified archive")
	}
}

func TestArchiveCorruptionFailsClosed(t *testing.T) {
	for _, kind := range []string{"changed", "missing", "extra", "identity", "version", "traversal"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			source := archiveFixtureSource(t, "alpha", "1")
			if err := archive.Commit(root, []archive.Source{source}, loadArchivedSnapshot); err != nil {
				t.Fatal(err)
			}
			_, entries, err := archive.Load(root, loadArchivedSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(entries[0].Dir, "process", "processes.json")
			switch kind {
			case "changed":
				err = os.WriteFile(path, []byte("[]"), 0600)
			case "missing":
				err = os.Remove(path)
			case "extra":
				err = os.WriteFile(filepath.Join(entries[0].Dir, "extra.json"), []byte("{}"), 0600)
			default:
				manifestPath := filepath.Join(filepath.Dir(filepath.Dir(entries[0].Dir)), "commit.json")
				raw, readErr := os.ReadFile(manifestPath)
				if readErr != nil {
					t.Fatal(readErr)
				}
				switch kind {
				case "identity":
					raw = bytes.ReplaceAll(raw, []byte(`"host_id": "alpha"`), []byte(`"host_id": "wrong"`))
				case "version":
					raw = bytes.ReplaceAll(raw, []byte(`"version": 1`), []byte(`"version": 99`))
				case "traversal":
					raw = bytes.ReplaceAll(raw, []byte(`"dir": "000000"`), []byte(`"dir": "../outside"`))
				}
				err = os.WriteFile(manifestPath, raw, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			repository, entries, err := archive.Load(root, loadArchivedSnapshot)
			if err == nil || repository != nil || entries != nil {
				t.Fatalf("corruption accepted: %v", err)
			}
		})
	}
}

func TestArchiveIncompleteStagesAndWriterLock(t *testing.T) {
	root := t.TempDir()
	source := archiveFixtureSource(t, "alpha", "1")
	if err := os.Mkdir(filepath.Join(root, ".stage-interrupted"), 0700); err != nil {
		t.Fatal(err)
	}
	repository, _, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil || repository.Len() != 0 {
		t.Fatalf("incomplete stage visible: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".ingest.lock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := archive.Commit(root, []archive.Source{source}, loadArchivedSnapshot); !errors.Is(err, archive.ErrWriterBusy) {
		t.Fatalf("writer lock: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, ".ingest.lock")); err != nil {
		t.Fatal("another writer's lock removed")
	}
	if err := archive.Commit(filepath.Join(source.Dir, "nested-archive"), []archive.Source{source}, loadArchivedSnapshot); err == nil {
		t.Fatal("recursive source accepted")
	}
}

func TestArchiveRejectsSymlinkEvidence(t *testing.T) {
	source := archiveFixtureSource(t, "alpha", "1")
	if err := os.Symlink(filepath.Join(source.Dir, "manifest.json"), filepath.Join(source.Dir, "linked.json")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root := t.TempDir()
	if err := archive.Commit(root, []archive.Source{source}, loadArchivedSnapshot); err == nil {
		t.Fatal("symlink evidence accepted")
	}
	repository, _, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil || repository.Len() != 0 {
		t.Fatal("symlink batch was published")
	}
}

func TestArchiveRejectsNestedDestinationThroughParentAlias(t *testing.T) {
	source := archiveFixtureSource(t, "alpha", "1")
	alias := filepath.Join(t.TempDir(), "source-alias")
	if err := os.Symlink(source.Dir, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	destination := filepath.Join(alias, "nested-archive")
	if err := archive.Commit(destination, []archive.Source{source}, loadArchivedSnapshot); err == nil {
		t.Fatal("parent alias bypassed recursive-copy guard")
	}
	if _, err := os.Stat(filepath.Join(source.Dir, "nested-archive")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rejected destination changed the source case")
	}
}

func TestArchiveQueriesMatchOriginalSnapshot(t *testing.T) {
	source := archiveFixtureSource(t, "alpha", "1")
	original, err := loadCentralView(source.View.CaseID, source.Dir)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := archive.Commit(root, []archive.Source{source}, loadArchivedSnapshot); err != nil {
		t.Fatal(err)
	}
	repository, _, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	recovered, _ := repository.Open(source.View)
	want, err := original.Store.QueryTimeline(store.TimelineQueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := recovered.QueryTimeline(store.TimelineQueryOptions{})
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Timeline changed: %+v vs %+v (%v)", got, want, err)
	}
	wantSearch, err := original.Store.SearchInvestigation(store.InvestigationSearchOptions{Query: "needle", Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	gotSearch, err := recovered.SearchInvestigation(store.InvestigationSearchOptions{Query: "needle", Limit: 1})
	if err != nil || !reflect.DeepEqual(gotSearch, wantSearch) {
		t.Fatalf("Search changed: %+v vs %+v (%v)", gotSearch, wantSearch, err)
	}
}
