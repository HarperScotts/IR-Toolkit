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
	"strings"
	"testing"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	localstore "ir-toolkit/internal/store/local"
)

func TestLinuxLoginEvidenceAPI(t *testing.T) {
	root := t.TempDir()
	content := []byte("Oct 16 12:00:00 host sshd[42]: Failed password for invalid user test from 192.0.2.1 port 22 ssh2\n2026-10-16T12:00:00Z host sshd[43]: Accepted password for test from 192.0.2.1 port 22 ssh2\n")
	sum := sha256.Sum256(content)
	analysis := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxArtifacts: []model.LinuxLoginArtifact{{Path: "/var/log/auth.log", Kind: "auth_log", Status: "observed", Content: content, SHA256: fmt.Sprintf("%x", sum)}}}, model.NetworkAnalysis{})
	if err := os.Mkdir(filepath.Join(root, "analysis"), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "analysis/login_analysis.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: localstore.New(root)}
	for path, marker := range map[string]string{"/": "linux-login-form", "/linux-logins.js": "/api/linux-logins?"} {
		rec := httptest.NewRecorder()
		server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), marker) {
			t.Fatalf("native UI asset %s: %d", path, rec.Code)
		}
	}
	for _, check := range []struct {
		query string
		total int
	}{
		{"since=2026-10-16T14:00:00%2B02:00&until=2026-10-16T12:00:00Z", 2},
		{"since=2026-10-16T12:00:00Z&until=2026-10-16T12:00:00Z&unknown_time=exclude", 1},
		{"since=2026-10-16T12:00:00.000000001Z&unknown_time=exclude", 0},
		{"until=2026-10-16T11:59:59Z&unknown_time=only", 1},
	} {
		rec := httptest.NewRecorder()
		server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/linux-logins?"+check.query, nil))
		var body struct {
			Total   int                           `json:"total"`
			Sources []model.LinuxLoginParseSource `json:"sources"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 || body.Total != check.total || len(body.Sources) != 1 {
			t.Fatalf("window %s: %d %s %v", check.query, rec.Code, rec.Body.String(), err)
		}
	}
	for _, test := range []struct {
		path   string
		status int
	}{
		{"/api/linux-logins?outcome=failed&limit=1", 200},
		{"/api/linux-logins/detail?id=" + analysis.LinuxRecords[0].ID, 200},
		{"/api/linux-logins?outcome=success", 400},
		{"/api/linux-logins?ip=hostname.example", 400},
		{"/api/linux-logins?since=2026-10-16T00:00:00Z&until=2026-10-16T00:00:00Z&unknown_time=only", 200},
		{"/api/linux-logins?since=2026-10-16T00:00:00", 400},
		{"/api/linux-logins?since=2026-10-17T00:00:00Z&until=2026-10-16T00:00:00Z", 400},
		{"/api/linux-logins?unknown_time=guess", 400},
		{"/api/linux-logins/detail", 400},
		{"/api/linux-logins/detail?id=unknown", 404},
	} {
		rec := httptest.NewRecorder()
		server.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, test.path, nil))
		if rec.Code != test.status {
			t.Fatal(test, rec.Code, rec.Body.String())
		}
		if test.status == 200 && !json.Valid(rec.Body.Bytes()) {
			t.Fatal("invalid native JSON")
		}
	}
}
