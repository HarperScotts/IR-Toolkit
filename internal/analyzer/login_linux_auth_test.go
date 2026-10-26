package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
)

func linuxLoginFixture(path, text string) model.LinuxLoginArtifact {
	sum := sha256.Sum256([]byte(text))
	return model.LinuxLoginArtifact{Path: path, Kind: "auth_log", Status: "observed", Content: []byte(text), SHA256: fmt.Sprintf("%x", sum)}
}

func TestLinuxSSHClaimsNotWindowsSessions(t *testing.T) {
	text := "Oct 16 12:00:00 host sshd[123]: Accepted publickey for Alice from 192.0.2.1 port 50123 ssh2: ED25519 SHA256:example\n2026-10-16T12:01:02+08:00 host sshd-session[456]: Failed password for invalid user bob from 2001:db8::1 port 12345 ssh2\nOct 16 12:02:00 host sudo[8]: a different message\n"
	a := linuxLoginFixture("/var/log/auth.log", text)
	before := bytes.Clone(a.Content)
	result := AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxArtifacts: []model.LinuxLoginArtifact{a}}, model.NetworkAnalysis{Processes: []model.ProcessNetworkAnalysis{{PID: 123, AuthenticationID: "0x123"}}})
	if len(result.LinuxRecords) != 2 || len(result.Sessions) != 0 || len(result.Findings) != 0 || result.Statistics.FailedLoginCount != 0 || result.Statistics.SessionCount != 0 {
		t.Fatal("Linux claims became Windows evidence", result)
	}
	first, second := result.LinuxRecords[0], result.LinuxRecords[1]
	if first.User != "Alice" || first.Outcome != "accepted" || !first.Timestamp.IsZero() || first.TimeBasis != "unknown" || first.ReportedPID != "123" || first.Line != 1 || first.SourceSHA256 != a.SHA256 || !strings.HasPrefix(first.ID, "linux-login:") {
		t.Fatal(first)
	}
	if second.Outcome != "failed" || !second.InvalidUserReported || second.User != "bob" || second.SourceIP != "2001:db8::1" || second.Timestamp.IsZero() || second.TimeBasis != "explicit_offset" || second.Program != "sshd-session" {
		t.Fatal(second)
	}
	if result.LinuxStatistics.RecordCount != 2 || result.LinuxStatistics.ReportedAccepted != 1 || result.LinuxStatistics.ReportedFailed != 1 || result.LinuxStatistics.UnknownTimeCount != 1 || result.LinuxSources[0].IgnoredLines != 1 || !bytes.Equal(before, a.Content) {
		t.Fatal(result)
	}
	// Same log text in another source is retained independently, not collapsed
	// into an inferred unique attempt or session.
	b := linuxLoginFixture("/var/log/secure", text)
	records, _, stats, _ := analyzeLinuxLogin(context.Background(), []model.LinuxLoginArtifact{a, b})
	if len(records) != 4 || records[0].ID == records[2].ID || stats.ReportedAccepted != 2 {
		t.Fatal("source identity collapsed")
	}
}

func TestLinuxSSHUnknownAndIncompleteEvidence(t *testing.T) {
	line := "Oct 16 12:00:00 host sshd[1]: Accepted password for a from 127.0.0.1 port 12 ssh2"
	for _, test := range []struct {
		name, text string
		want       int
		partial    bool
	}{
		{"unterminated", line, 0, true},
		{"valid prefix only", line + "\n" + line, 1, true},
		{"invalid address", strings.Replace(line, "127.0.0.1", "hostname.example", 1) + "\n", 0, true},
		{"invalid port", strings.Replace(line, "port 12", "port 99999", 1) + "\n", 0, true},
		{"offset missing", strings.Replace(line, "Oct 16 12:00:00", "2026-10-16T12:00:00", 1) + "\n", 1, true},
		{"injected occurrence", "Oct 16 12:00:00 host app[1]: quoted " + line + "\n", 0, false},
		{"partial auth", strings.Replace(line, "Accepted", "Partial", 1) + "\n", 0, false},
		{"other format", "not-a-timestamp host sshd[1]: Accepted password for a from 127.0.0.1 port 12 ssh2\n", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			records, sources, _, _ := analyzeLinuxLogin(context.Background(), []model.LinuxLoginArtifact{linuxLoginFixture("/var/log/auth.log", test.text)})
			if len(records) != test.want || (sources[0].Status == "partial") != test.partial {
				t.Fatal(records, sources)
			}
		})
	}
	for _, test := range []struct {
		name   string
		mutate func(*model.LinuxLoginArtifact)
	}{
		{"hash", func(a *model.LinuxLoginArtifact) { a.SHA256 = "bad" }},
		{"status", func(a *model.LinuxLoginArtifact) { a.Status = "error" }},
		{"binary", func(a *model.LinuxLoginArtifact) { a.Content = []byte{0, 255} }},
		{"accounting", func(a *model.LinuxLoginArtifact) { a.Kind = "historical_accounting" }},
		{"link", func(a *model.LinuxLoginArtifact) { a.LinkTarget = "/elsewhere" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := linuxLoginFixture("/var/log/auth.log", line+"\n")
			test.mutate(&a)
			records, sources, _, _ := analyzeLinuxLogin(context.Background(), []model.LinuxLoginArtifact{a})
			if len(records) > 0 || sources[0].Status != "skipped" {
				t.Fatal(records, sources)
			}
		})
	}
	a := linuxLoginFixture("/var/log/auth.log", line+"\n")
	if records, _, _, _ := analyzeLinuxLogin(context.Background(), []model.LinuxLoginArtifact{a, a}); len(records) > 0 {
		t.Fatal("duplicate source parsed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if records, _, _, warnings := analyzeLinuxLogin(ctx, []model.LinuxLoginArtifact{a}); len(records) > 0 || !strings.Contains(strings.Join(warnings, " "), "cancelled") {
		t.Fatal("cancel hidden")
	}
}

func FuzzLinuxSSHAuthentication(f *testing.F) {
	f.Add("Oct 16 12:00:00 host sshd[1]: Accepted password for a from 127.0.0.1 port 12 ssh2\n")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 1<<20 {
			t.Skip()
		}
		a := linuxLoginFixture("/var/log/auth.log", text)
		before := bytes.Clone(a.Content)
		records, _, _, _ := analyzeLinuxLogin(context.Background(), []model.LinuxLoginArtifact{a})
		if len(records) > 16384 || !bytes.Equal(before, a.Content) {
			t.Fatal("bounds or source mutation")
		}
		seen := map[string]bool{}
		for _, record := range records {
			if seen[record.ID] || record.Line <= 0 || record.SourceSHA256 != a.SHA256 || record.TimeBasis == "unknown" && !record.Timestamp.IsZero() {
				t.Fatal("identity/time invariant")
			}
			seen[record.ID] = true
		}
	})
}
