package local

import (
	"reflect"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
)

func TestLinuxPersistenceInventoryQueries(t *testing.T) {
	root := t.TempDir()
	uid := uint32(0)
	snapshot := model.PersistenceSnapshot{
		Services:     []model.ServiceInfo{{Name: "legacy"}},
		LinuxSources: []model.LinuxPersistenceSource{{Path: "/etc/cron.d", Kind: "cron", Status: "observed"}},
		LinuxArtifacts: []model.LinuxPersistenceArtifact{
			{Kind: "systemd", Path: "/etc/systemd/system/A.service", Content: []byte("UPPER"), UID: &uid},
			{Kind: "systemd", Path: "/etc/systemd/system/a.service", Content: []byte("lower"), ModifiedAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)},
			{Kind: "cron", Path: "/etc/cron.d/entry", ReadError: "denied"},
		},
	}
	writeFixtureJSON(t, root, "persistence/persistence.json", snapshot)
	local := New(root)
	central, err := centralstore.New(store.CaseView{CaseID: "linux", HostID: "host", Version: "1"}, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []store.CaseStore{local, central} {
		result, err := backend.QueryPersistence(store.PersistenceQueryOptions{Type: "linux_systemd", Page: store.QueryPageOptions{Limit: 1}})
		if err != nil || result.Total != 2 || len(result.Items) != 1 || !result.Page.HasMore || result.Items[0].Name != "/etc/systemd/system/a.service" {
			t.Fatalf("inventory pagination/sort: %+v %v", result, err)
		}
		all, err := backend.QueryPersistence(store.PersistenceQueryOptions{})
		if err != nil || all.Total != 4 {
			t.Fatal(all, err)
		}
		ids := map[string]bool{}
		for _, item := range all.Items {
			if ids[item.ID] {
				t.Fatal("case-sensitive paths collapsed", item)
			}
			ids[item.ID] = true
			got, found, err := backend.PersistenceItemByID(item.ID)
			if err != nil || !found || !reflect.DeepEqual(got, item) {
				t.Fatal("detail identity mismatch", err)
			}
			if item.Type != "service" && (item.Finding != nil || item.PID != 0 || item.Command != "" || item.User != "") {
				t.Fatal("inventory invented semantics", item)
			}
		}
		if !ids["persistence:service:legacy:"] {
			t.Fatal("legacy Windows ID changed")
		}
	}
	copy, err := central.PersistenceSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	copy.LinuxArtifacts[0].Content[0] = 'X'
	*copy.LinuxArtifacts[0].UID = 42
	copy.LinuxSources[0].Status = "mutated"
	again, err := central.PersistenceSnapshot()
	if err != nil || string(again.LinuxArtifacts[0].Content) != "UPPER" || *again.LinuxArtifacts[0].UID != 0 || again.LinuxSources[0].Status != "observed" {
		t.Fatal("central Linux snapshot mutation leaked", err)
	}
}

func TestLinuxConfigExactDetailBinding(t *testing.T) {
	for _, test := range []struct {
		name, hash string
		duplicate  bool
		want       bool
	}{
		{"matching", "source-hash", false, true}, {"stale", "old-hash", false, false}, {"duplicate", "source-hash", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			artifact := model.LinuxPersistenceArtifact{Path: "/etc/systemd/system/A.service", Kind: "systemd", SHA256: "source-hash"}
			config := model.LinuxPersistenceConfig{Path: artifact.Path, Kind: artifact.Kind, SHA256: test.hash, Activation: "unknown", Status: "observed_syntax", Directives: []model.LinuxConfigDirective{{Line: 2, EndLine: 2, Section: "Service", Key: "ExecStart", Value: "/bin/true"}}}
			analysis := model.PersistenceAnalysis{LinuxConfigs: []model.LinuxPersistenceConfig{config}}
			if test.duplicate {
				analysis.LinuxConfigs = append(analysis.LinuxConfigs, config)
			}
			writeFixtureJSON(t, root, "persistence/persistence.json", model.PersistenceSnapshot{LinuxArtifacts: []model.LinuxPersistenceArtifact{artifact}})
			writeFixtureJSON(t, root, "analysis/persistence_analysis.json", analysis)
			local := New(root)
			central, err := centralstore.New(store.CaseView{CaseID: "case", HostID: "host", Version: "1"}, local)
			if err != nil {
				t.Fatal(err)
			}
			for _, backend := range []store.CaseStore{local, central} {
				items, err := backend.QueryPersistence(store.PersistenceQueryOptions{})
				if err != nil || len(items.Items) != 1 || items.Items[0].LinuxConfig != nil {
					t.Fatal("parsed payload leaked into list", err)
				}
				detail, found, err := backend.PersistenceItemByID(items.Items[0].ID)
				if err != nil || !found || (detail.LinuxConfig != nil) != test.want {
					t.Fatal("wrong exact config binding", detail, err)
				}
			}
			if test.want {
				item, _, _ := central.PersistenceItemByID(linuxPersistenceItem(artifact).ID)
				item.LinuxConfig.Directives[0].Value = "mutated"
				again, _, _ := central.PersistenceItemByID(item.ID)
				if again.LinuxConfig.Directives[0].Value != "/bin/true" {
					t.Fatal("central parsed config copy leaked")
				}
			}
		})
	}
}
