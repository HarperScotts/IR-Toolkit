package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	localstore "ir-toolkit/internal/store/local"
)

func TestLinuxPersistenceDetailRawEvidence(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "persistence"), 0700); err != nil {
		t.Fatal(err)
	}
	artifact := model.LinuxPersistenceArtifact{Kind: "cron", Path: "/etc/cron.d/example", Content: []byte("# raw\x00\xff\n"), SHA256: "fixture-hash", Mode: "-rw-------"}
	data, err := json.Marshal(model.PersistenceSnapshot{LinuxArtifacts: []model.LinuxPersistenceArtifact{artifact}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "persistence/persistence.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	backend := localstore.New(root)
	if err := os.Mkdir(filepath.Join(root, "analysis"), 0700); err != nil {
		t.Fatal(err)
	}
	config := model.LinuxPersistenceConfig{Path: artifact.Path, Kind: artifact.Kind, SHA256: artifact.SHA256, Activation: "unknown", Status: "partial", Warnings: []string{"fixture diagnostic"}}
	parsed, err := json.Marshal(model.PersistenceAnalysis{LinuxConfigs: []model.LinuxPersistenceConfig{config}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "analysis/persistence_analysis.json"), parsed, 0600); err != nil {
		t.Fatal(err)
	}
	items, err := backend.QueryPersistence(store.PersistenceQueryOptions{})
	if err != nil || len(items.Items) != 1 {
		t.Fatal(items, err)
	}
	server := &Server{store: backend}
	recorder := httptest.NewRecorder()
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/persistence/detail?id="+items.Items[0].ID, nil))
	if recorder.Code != http.StatusOK {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	var response PersistenceDetailResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.LinuxArtifact == nil || response.LinuxArtifact.Path != artifact.Path || !bytes.Equal(response.LinuxArtifact.Content, artifact.Content) || response.Service != nil || response.ScheduledTask != nil || response.Finding != nil {
		t.Fatalf("lost or reinterpreted raw Linux source: %+v", response)
	}
	if response.LinuxConfig == nil || response.LinuxConfig.Activation != "unknown" || response.LinuxConfig.Warnings[0] != "fixture diagnostic" {
		t.Fatal("parsed diagnostics lost", response)
	}
}
