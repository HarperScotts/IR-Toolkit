package local

import (
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
)

func TestSystemdMergeDetailInputBinding(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*model.PersistenceSnapshot, *model.PersistenceAnalysis)
		want   bool
	}{
		{"matching", func(*model.PersistenceSnapshot, *model.PersistenceAnalysis) {}, true},
		{"v2 matching", func(_ *model.PersistenceSnapshot, a *model.PersistenceAnalysis) {
			a.LinuxSystemdMerges[0].Profile = "observed-system-service-v2"
			a.LinuxSystemdMerges[0].NameKind = "plain"
			a.LinuxSystemdMerges[0].BaseLookup = "exact"
		}, true},
		{"changed bytes without changed claimed hash", func(s *model.PersistenceSnapshot, _ *model.PersistenceAnalysis) {
			s.LinuxArtifacts[0].Content = []byte("changed")
		}, false},
		{"new dropin", func(s *model.PersistenceSnapshot, _ *model.PersistenceAnalysis) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service.d/new.conf"})
		}, false},
		{"changed coverage", func(s *model.PersistenceSnapshot, _ *model.PersistenceAnalysis) { s.LinuxSources[0].Status = "partial" }, false},
		{"changed read error", func(s *model.PersistenceSnapshot, _ *model.PersistenceAnalysis) {
			s.LinuxArtifacts[0].ReadError = "denied"
		}, false},
		{"unknown profile", func(_ *model.PersistenceSnapshot, a *model.PersistenceAnalysis) {
			a.LinuxSystemdMerges[0].Profile = "future"
		}, false},
		{"duplicate merge", func(_ *model.PersistenceSnapshot, a *model.PersistenceAnalysis) {
			a.LinuxSystemdMerges = append(a.LinuxSystemdMerges, a.LinuxSystemdMerges[0])
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			artifact := model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service", SHA256: "fixture", Content: []byte("source")}
			snapshot := model.PersistenceSnapshot{LinuxArtifacts: []model.LinuxPersistenceArtifact{artifact}, LinuxSources: []model.LinuxPersistenceSource{{Path: "/etc/systemd/system", Kind: "systemd", Status: "observed"}}}
			merge := model.LinuxSystemdMerge{Unit: "demo.service", Scope: "system", Profile: "observed-system-service-v1", InputDigest: model.LinuxPersistenceInputDigest(snapshot), Status: "observed_subset", Activation: "unknown", Sources: []model.LinuxSystemdMergeSource{{Path: artifact.Path, Decision: "selected"}}, Settings: []model.LinuxSystemdSetting{{Key: "User", Values: []model.LinuxSystemdValue{{Value: "nobody"}}}}}
			analysis := model.PersistenceAnalysis{LinuxSystemdMerges: []model.LinuxSystemdMerge{merge}}
			test.mutate(&snapshot, &analysis)
			writeFixtureJSON(t, root, "persistence/persistence.json", snapshot)
			writeFixtureJSON(t, root, "analysis/persistence_analysis.json", analysis)
			local := New(root)
			central, err := centralstore.New(store.CaseView{CaseID: "case", HostID: "host", Version: "1"}, local)
			if err != nil {
				t.Fatal(err)
			}
			id := linuxPersistenceItem(artifact).ID
			for _, backend := range []store.CaseStore{local, central} {
				items, err := backend.QueryPersistence(store.PersistenceQueryOptions{})
				if err != nil || len(items.Items) == 0 || len(items.Items[0].LinuxSystemdMerges) != 0 {
					t.Fatal("merge payload leaked to list", err)
				}
				detail, found, err := backend.PersistenceItemByID(id)
				if err != nil || !found || (len(detail.LinuxSystemdMerges) == 1) != test.want {
					t.Fatal("stale or missing merge binding", detail, err)
				}
			}
			if test.want {
				first, _, _ := central.PersistenceItemByID(id)
				first.LinuxSystemdMerges[0].Settings[0].Values[0].Value = "mutated"
				again, _, _ := central.PersistenceItemByID(id)
				if again.LinuxSystemdMerges[0].Settings[0].Values[0].Value != "nobody" {
					t.Fatal("central merge result mutated")
				}
			}
		})
	}
}
