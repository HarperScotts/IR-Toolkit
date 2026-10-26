package central_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
	"ir-toolkit/internal/store/central"
	"ir-toolkit/internal/store/local"
)

func TestArchiveRestartPreservesAllScopedEvidenceIDs(t *testing.T) {
	root := t.TempDir()
	sources := []archive.Source{
		{View: store.CaseView{CaseID: "case", HostID: "alpha", Version: "1"}, Dir: t.TempDir()},
		{View: store.CaseView{CaseID: "case", HostID: "beta", Version: "1"}, Dir: t.TempDir()},
	}
	for _, source := range sources {
		for path, raw := range detailFixtureFiles {
			writeDetailFixture(t, source.Dir, path, strings.ReplaceAll(raw, "HOST", source.View.HostID))
		}
	}
	loader := func(view store.CaseView, dir string) (store.CaseStore, error) {
		// These minimal fixtures omit overview domains. No production command uses
		// this loader; the CLI tests separately exercise full-case validation.
		snapshot := local.New(dir)
		return snapshot, nil
	}
	if err := archive.Commit(root, sources, loader); err != nil {
		t.Fatal(err)
	}
	repository, _, err := archive.Load(root, loader)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := central.NewInvestigator(repository)
	expected := map[string]store.ScopedEvidenceDetail{}
	for _, source := range sources {
		for _, fixture := range detailFixtureCases {
			detail, found, err := original.EvidenceDetail(source.View, fixture.typeName, fixture.id)
			if err != nil || !found {
				t.Fatalf("original %s: %v", fixture.typeName, err)
			}
			expected[source.View.HostID+"/"+fixture.typeName] = detail
		}
		// Remove the original source files, not any committed archive data.
		for path := range detailFixtureFiles {
			if err := os.Remove(filepath.Join(source.Dir, filepath.FromSlash(path))); err != nil {
				t.Fatal(err)
			}
		}
	}
	recovered, _, err := archive.Load(root, loader)
	if err != nil {
		t.Fatal(err)
	}
	investigator, _ := central.NewInvestigator(recovered)
	for _, source := range sources {
		for _, fixture := range detailFixtureCases {
			t.Run(source.View.HostID+"/"+fixture.typeName, func(t *testing.T) {
				detail, found, err := investigator.EvidenceDetail(source.View, fixture.typeName, fixture.id)
				if err != nil || !found || !reflect.DeepEqual(detail, expected[source.View.HostID+"/"+fixture.typeName]) {
					t.Fatalf("recovered detail differs: %+v, %v", detail, err)
				}
				search, err := investigator.SearchInvestigation(store.MultiHostSearchOptions{Views: []store.CaseView{source.View}, Search: store.InvestigationSearchOptions{Query: "needle", Types: map[string]bool{fixture.typeName: true}}})
				if err != nil {
					t.Fatal(err)
				}
				foundID := false
				for _, item := range search.Items {
					if item.Item.ID == fixture.id {
						foundID = true
					}
				}
				if !foundID {
					t.Fatalf("Search ID changed for %s: %+v", fixture.id, search)
				}
			})
		}
	}
}
