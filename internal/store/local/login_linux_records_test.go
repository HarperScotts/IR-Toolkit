package local

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
)

func TestLinuxLoginNativeStoreContract(t *testing.T) {
	root := t.TempDir()
	a := model.LinuxLoginArtifact{Path: "/var/log/auth.log", Kind: "auth_log", Status: "observed", Content: []byte("2026-10-16T12:00:00Z host sshd[1]: Accepted password for Alice from 192.0.2.1 port 12 ssh2\nOct 16 12:01:00 host sshd[2]: Failed password for alice from 192.0.2.2 port 13 ssh2\n"), SHA256: ""}
	// Build actual Analyzer output rather than a mock native login query result.
	setLinuxLoginFixtureHash(&a)
	analysis := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxArtifacts: []model.LinuxLoginArtifact{a}}, model.NetworkAnalysis{})
	analysis.Sessions = []model.LoginSessionAnalysis{{LogonID: "0x42", User: "legacy"}}
	writeFixtureJSON(t, root, "analysis/login_analysis.json", analysis)
	local := New(root)
	central, err := centralstore.New(store.CaseView{CaseID: "case", HostID: "host", Version: "1"}, local)
	if err != nil {
		t.Fatal(err)
	}
	for _, backend := range []store.CaseStore{local, central} {
		boundary := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
		for _, check := range []struct {
			since, until time.Time
			policy       string
			total        uint32
		}{
			{boundary, boundary, "include", 2},
			{boundary, boundary, "exclude", 1},
			{boundary.Add(time.Nanosecond), time.Time{}, "include", 1},
			{time.Time{}, boundary.Add(-time.Nanosecond), "exclude", 0},
			{boundary, boundary, "only", 1},
		} {
			got, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{Since: check.since, Until: check.until, UnknownTime: check.policy})
			if err != nil || got.Total != check.total {
				t.Fatalf("window %+v: %+v %v", check, got, err)
			}
		}
		for _, invalid := range []store.LinuxLoginQueryOptions{{Since: boundary.Add(time.Second), Until: boundary}, {UnknownTime: "guess"}} {
			if _, err := backend.QueryLinuxLogins(invalid); err == nil {
				t.Fatal("invalid window accepted")
			}
		}
		page, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{Page: store.QueryPageOptions{Limit: 1}})
		if err != nil || page.Total != 2 || len(page.Items) != 1 || !page.Page.HasMore || page.Items[0].Timestamp.IsZero() {
			t.Fatal(page, err)
		}
		second, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{Page: store.QueryPageOptions{Offset: 1, Limit: 1}})
		if err != nil || len(second.Items) != 1 || !second.Items[0].Timestamp.IsZero() {
			t.Fatal("unknown time sorting", second, err)
		}
		for _, item := range append(page.Items, second.Items...) {
			record, found, err := backend.LinuxLoginRecordByID(item.ID)
			if err != nil || !found || record != item {
				t.Fatal("native ID changed", record, err)
			}
		}
		filtered, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{User: "Alice", Outcome: "accepted", IP: "192.0.2.1"})
		if err != nil || filtered.Total != 1 {
			t.Fatal(filtered, err)
		}
		legacy, err := backend.QueryLogins(store.LoginQueryOptions{})
		if err != nil || legacy.Total != 1 || legacy.Items[0].User != "legacy" {
			t.Fatal("native records mixed into Windows sessions", legacy, err)
		}
	}
	copy, err := central.LoginAnalysis()
	if err != nil {
		t.Fatal(err)
	}
	copy.LinuxRecords[0].User = "mutated"
	copy.LinuxSources[0].Path = "mutated"
	copy.LinuxStatistics.RecordCount = 999
	again, err := central.LoginAnalysis()
	if err != nil || again.LinuxRecords[0].User != "Alice" || again.LinuxSources[0].Path != a.Path || again.LinuxStatistics.RecordCount != 2 {
		t.Fatal("central native snapshot mutated", err)
	}
	missing := New(t.TempDir())
	if _, err := missing.QueryLinuxLogins(store.LinuxLoginQueryOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing evidence error swallowed", err)
	}
}

func TestLinuxLoginDuplicateIDsFailNativeQuery(t *testing.T) {
	root := t.TempDir()
	id := "linux-login:" + strings.Repeat("a", 64)
	writeFixtureJSON(t, root, "analysis/login_analysis.json", model.LoginAnalysis{LinuxRecords: []model.LinuxLoginRecord{{ID: id}, {ID: id}}})
	backend := New(root)
	if _, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{}); err == nil {
		t.Fatal("duplicate native ID returned as successful query")
	}
	if _, _, err := backend.LinuxLoginRecordByID(id); err == nil {
		t.Fatal("duplicate native ID resolved arbitrarily")
	}
}
