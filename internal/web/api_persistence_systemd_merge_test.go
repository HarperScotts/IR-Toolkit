package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	localstore "ir-toolkit/internal/store/local"
)

func TestSystemdMergeAPIEndToEnd(t *testing.T) {
	root := t.TempDir()
	content := []byte("[Service]\nExecStart=/bin/true\nUser=nobody\n")
	hash := sha256.Sum256(content)
	snapshot := model.PersistenceSnapshot{LinuxArtifacts: []model.LinuxPersistenceArtifact{{Kind: "systemd", Path: "/etc/systemd/system/demo.service", Content: content, SHA256: fmt.Sprintf("%x", hash)}}}
	for _, name := range []string{"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/generator.late"} {
		snapshot.LinuxSources = append(snapshot.LinuxSources, model.LinuxPersistenceSource{Path: name, Kind: "systemd", Status: "observed"})
	}
	analysis := analyzer.AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	for name, value := range map[string]any{"persistence/persistence.json": snapshot, "analysis/persistence_analysis.json": analysis} {
		file := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	backend := localstore.New(root)
	items, err := backend.QueryPersistence(store.PersistenceQueryOptions{})
	if err != nil || len(items.Items) != 1 {
		t.Fatal(items, err)
	}
	recorder := httptest.NewRecorder()
	server := &Server{store: backend}
	server.routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/persistence/detail?id="+items.Items[0].ID, nil))
	var response PersistenceDetailResponse
	if recorder.Code != 200 || json.Unmarshal(recorder.Body.Bytes(), &response) != nil {
		t.Fatal(recorder.Code, recorder.Body.String())
	}
	if len(response.LinuxSystemdMerges) != 1 || response.LinuxSystemdMerges[0].Status != "observed_subset" || response.LinuxSystemdMerges[0].Activation != "unknown" || response.Finding != nil {
		t.Fatal("merge API lost uncertainty", response)
	}
}
