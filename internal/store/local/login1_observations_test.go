package local

import (
	"context"
	"errors"
	"os"
	"testing"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
	"ir-toolkit/internal/testutil"
)

func TestLogin1LocalCentralContract(t *testing.T) {
	source := testutil.Login1Snapshot()
	a := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxLogin1: &source}, model.NetworkAnalysis{})
	root := t.TempDir()
	writeFixtureJSON(t, root, "analysis/login_analysis.json", a)
	local := New(root)
	central, err := centralstore.New(store.CaseView{CaseID: "case", HostID: "host", Version: "1"}, local)
	if err != nil {
		t.Fatal(err)
	}
	no := false
	for _, backend := range []store.CaseStore{local, central} {
		all, err := backend.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{Page: store.QueryPageOptions{Limit: 1}})
		if err != nil || all.Total != 2 || len(all.Items) != 1 || !all.Page.HasMore {
			t.Fatal(all, err)
		}
		filtered, err := backend.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{Active: &no, User: "Alice", State: "online"})
		if err != nil || filtered.Total != 1 || filtered.Items[0].Properties.Active == nil || *filtered.Items[0].Properties.Active {
			t.Fatal(filtered, err)
		}
		unknown, err := backend.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{User: "alice", Active: &no})
		if err != nil || unknown.Total != 0 {
			t.Fatal("unknown matched false or user case lost", unknown, err)
		}
		detail, found, err := backend.LinuxLogin1ByID(filtered.Items[0].ID)
		if err != nil || !found || detail.SourceCall == nil || detail.SourceCall.SHA256 != source.Calls[3].SHA256 {
			t.Fatal(detail, found, err)
		}
		legacy, err := backend.QueryLogins(store.LoginQueryOptions{})
		if err != nil || legacy.Total != 0 {
			t.Fatal("mixed Windows sessions", legacy, err)
		}
		ssh, err := backend.QueryLinuxLogins(store.LinuxLoginQueryOptions{})
		if err != nil || ssh.Total != 0 {
			t.Fatal("mixed SSH claims", ssh, err)
		}
	}
	items, err := central.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{User: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	id := items.Items[0].ID
	*items.Items[0].Properties.Active = true
	items.Items[0].SourceCall.Content[0] = 'X'
	again, found, err := central.LinuxLogin1ByID(id)
	if err != nil || !found || *again.Properties.Active || again.SourceCall.Content[0] == 'X' {
		t.Fatal("Central snapshot mutated", err)
	}
	if _, err := New(t.TempDir()).QueryLinuxLogin1(store.LinuxLogin1QueryOptions{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing evidence swallowed", err)
	}
	for _, bad := range []string{"duplicate", "profile", "ID"} {
		t.Run(bad, func(t *testing.T) {
			s := testutil.Login1Snapshot()
			a := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxLogin1: &s}, model.NetworkAnalysis{})
			switch bad {
			case "duplicate":
				a.LinuxLogin1.Observations = append(a.LinuxLogin1.Observations, a.LinuxLogin1.Observations[0])
			case "profile":
				a.LinuxLogin1.Profile = "future"
			case "ID":
				a.LinuxLogin1.Observations[0].ID = "wrong"
			}
			root := t.TempDir()
			writeFixtureJSON(t, root, "analysis/login_analysis.json", a)
			backend := New(root)
			if _, err := backend.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{}); err == nil {
				t.Fatal("malformed analysis accepted")
			}
			if _, _, err := backend.LinuxLogin1ByID(id); err == nil {
				t.Fatal("malformed detail accepted")
			}
		})
	}
}
