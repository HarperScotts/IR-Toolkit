package analyzer

import (
	"context"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/testutil"
)

func TestLogin1NormalizationProvenanceAndUnknown(t *testing.T) {
	source := testutil.Login1Snapshot()
	result := AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxLogin1: &source}, model.NetworkAnalysis{})
	a := result.LinuxLogin1
	if a == nil || a.Status != "observed_subset" || len(a.Observations) != 2 || len(result.Sessions) != 0 || len(result.Findings) != 0 || result.Statistics.SessionCount != 0 {
		t.Fatalf("native observations leaked: %+v", result)
	}
	first, second := a.Observations[0], a.Observations[1]
	if first.Properties.Active == nil || *first.Properties.Active || first.Properties.Remote == nil || *first.Properties.Remote || first.Properties.Leader == nil || *first.Properties.Leader != 0 || first.Properties.TTY == nil || *first.Properties.TTY != "" || first.Properties.TimestampUS == nil || *first.Properties.TimestampUS != ^uint64(0) {
		t.Fatal("false, zero, empty or uint64 fidelity lost", first.Properties)
	}
	if second.Properties.Active != nil || second.Properties.State != nil {
		t.Fatal("missing became a value")
	}
	if first.ID == second.ID || !strings.HasPrefix(first.ID, "linux-login1:") || first.SourceCall.SHA256 != source.Calls[3].SHA256 || a.ListSHA256 != source.Calls[2].SHA256 {
		t.Fatal("lost provenance")
	}
	if !strings.Contains(string(first.SourceCall.Content), "FutureProperty") {
		t.Fatal("unknown property lost from raw evidence")
	}
	again := analyzeLogin1(context.Background(), &source)
	if again.Observations[0].ID != first.ID {
		t.Fatal("unstable evidence ID")
	}
	source.StartedAt = source.StartedAt.Add(-1)
	if analyzeLogin1(context.Background(), &source).Observations[0].ID == first.ID {
		t.Fatal("snapshot identity not scoped")
	}
}

func TestLogin1InvalidPropertyStaysUnknown(t *testing.T) {
	for _, data := range []string{
		`{"Active":{"type":"b","data":"false"},"Leader":{"type":"u","data":4294967296}}`,
		`{"Active":{"type":"s","data":"false"},"Leader":{"type":"u","data":-1}}`,
		`{"Active":{"type":"b","data":null}}`,
		`{"Active":{"type":"b","data":false},"Active":{"type":"b","data":true}}`,
		`{"Id":{"type":"s","data":"other"},"Active":{"type":"b","data":true}}`,
		`{"Active":{"type":"b","type":"s","data":false}}`,
	} {
		p, warnings := login1NormalizeProperties([]byte(data), "s1")
		if p.Active != nil || p.Leader != nil || len(warnings) == 0 {
			t.Fatalf("invalid became known: %s %+v %v", data, p, warnings)
		}
	}
}

func TestLogin1MalformedEvidenceAndPartial(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*model.LinuxLogin1Snapshot)
		want   string
		count  int
	}{
		{"source error", func(s *model.LinuxLogin1Snapshot) { s.Status = "error" }, "skipped", 0},
		{"bad list hash", func(s *model.LinuxLogin1Snapshot) { s.Calls[2].SHA256 = "bad" }, "skipped", 0},
		{"list mismatch", func(s *model.LinuxLogin1Snapshot) { s.Sessions[0].ReportedUID = 2 }, "skipped", 0},
		{"list duplicate", func(s *model.LinuxLogin1Snapshot) { s.Calls = append(s.Calls, s.Calls[2]) }, "skipped", 0},
		{"bad call reference", func(s *model.LinuxLogin1Snapshot) { s.Sessions[0].PropertiesCall = 2 }, "partial", 2},
		{"unread", func(s *model.LinuxLogin1Snapshot) { s.Sessions[0].PropertiesCall = -1 }, "partial", 2},
		{"property hash", func(s *model.LinuxLogin1Snapshot) { s.Calls[3].SHA256 = "bad" }, "partial", 2},
		{"property error", func(s *model.LinuxLogin1Snapshot) { s.Calls[3].Status = "error"; s.Calls[3].Error = "vanished" }, "partial", 2},
		{"partial source", func(s *model.LinuxLogin1Snapshot) { s.Status = "partial" }, "partial", 2},
		{"source call limit", func(s *model.LinuxLogin1Snapshot) {
			for len(s.Calls) < 70 {
				s.Calls = append(s.Calls, model.LinuxLogin1Call{})
			}
		}, "skipped", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := testutil.Login1Snapshot()
			test.mutate(&s)
			a := analyzeLogin1(context.Background(), &s)
			if a.Status != test.want || len(a.Observations) != test.count {
				t.Fatal(a)
			}
		})
	}
	s := testutil.Login1Snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := analyzeLogin1(ctx, &s)
	if a.Status != "partial" || len(a.Observations) != 0 {
		t.Fatal(a)
	}
}

func FuzzLogin1Properties(f *testing.F) {
	f.Add([]byte(`{"Active":{"type":"b","data":false}}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		_, _ = login1NormalizeProperties(data, "s1")
	})
}
