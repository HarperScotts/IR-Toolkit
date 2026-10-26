package web

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	localstore "ir-toolkit/internal/store/local"
	"ir-toolkit/internal/testutil"
)

func TestLogin1EvidenceAPI(t *testing.T) {
	source := testutil.Login1Snapshot()
	a := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxLogin1: &source}, model.NetworkAnalysis{})
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "analysis"), 0700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(a)
	if err := os.WriteFile(filepath.Join(root, "analysis/login_analysis.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{store: localstore.New(root)}
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/api/linux-login1?active=false", 200}, {"/api/linux-login1/detail?id=" + a.LinuxLogin1.Observations[0].ID, 200},
		{"/api/linux-login1?active=0", 400}, {"/api/linux-login1/detail", 400}, {"/api/linux-login1/detail?id=linux-login:other", 404},
		{"/api/linux-login1?since=2026-10-18T00:00:00Z", 400},
		{"/linux-login1.js", 200},
	} {
		rec := httptest.NewRecorder()
		s.routes().ServeHTTP(rec, httptest.NewRequest("GET", test.path, nil))
		if rec.Code != test.status {
			t.Fatal(test, rec.Code, rec.Body.String())
		}
	}
	rec := httptest.NewRecorder()
	s.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/linux-login1?active=false&limit=1", nil))
	var response struct {
		Total    int                            `json:"total"`
		Records  []model.LinuxLogin1Observation `json:"records"`
		Coverage map[string]any                 `json:"coverage"`
	}
	var wire struct {
		Records []struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"records"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil || len(wire.Records) != 1 || string(wire.Records[0].Properties["reported_creation_usec"]) != `"18446744073709551615"` {
		t.Fatal("uint64 creation value lost JSON string fidelity", rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Total != 1 || len(response.Records) != 1 || response.Records[0].SourceCall != nil || response.Records[0].Properties.Active == nil || *response.Records[0].Properties.Active || response.Coverage["list_sha256"] == nil {
		t.Fatal(response, err)
	}
	missing := &Server{store: localstore.New(t.TempDir())}
	rec = httptest.NewRecorder()
	missing.routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/linux-login1", nil))
	if rec.Code != 500 {
		t.Fatal("missing analysis treated as empty success")
	}
	if strings.Contains(string(data), `"logon_id"`) {
		t.Fatal("unexpected Windows identity")
	}
}
