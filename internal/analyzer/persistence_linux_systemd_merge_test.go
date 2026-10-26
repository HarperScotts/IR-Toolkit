package analyzer

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
)

func systemdMergeFixture(artifacts ...model.LinuxPersistenceArtifact) model.PersistenceSnapshot {
	snapshot := model.PersistenceSnapshot{LinuxArtifacts: artifacts}
	for _, source := range systemdSystemProfile {
		snapshot.LinuxSources = append(snapshot.LinuxSources, model.LinuxPersistenceSource{Path: source.root, Kind: "systemd", Status: "observed"})
	}
	return snapshot
}

func mergeFixtureResult(t *testing.T, snapshot model.PersistenceSnapshot) model.LinuxSystemdMerge {
	t.Helper()
	analysis := AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	if len(analysis.LinuxSystemdMerges) != 1 || len(analysis.Findings) != 0 {
		t.Fatalf("merge shape/findings: %+v", analysis)
	}
	return analysis.LinuxSystemdMerges[0]
}

func TestSystemdObservedPriorityAndReset(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service", "[Service]\nExecStart=/vendor\nUser=vendor\n"),
		linuxConfigFixture("systemd", "/run/systemd/system/demo.service", "[Service]\nExecStart=/runtime\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/demo.service", "[Service]\nExecStart=/admin\nUser=old\nEnvironment=OPAQUE=1\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/service.d/10-global.conf", "[Service]\nUser=global\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/demo.service.d/20-reset.conf", "[Service]\nExecStart=\nExecStart=/chosen\nUser=chosen\n"),
		linuxConfigFixture("systemd", "/run/systemd/system/demo.service.d/20-reset.conf", "[Service]\nExecStart=/shadowed\nUser=wrong\n"),
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service.d/30-late.conf", "[Service]\nExecStart=/second\nUser=late\n"),
	)
	before := model.LinuxPersistenceInputDigest(snapshot)
	result := mergeFixtureResult(t, snapshot)
	if result.Status != "observed_subset" || result.Activation != "unknown" || result.InputDigest != before {
		t.Fatal(result)
	}
	settings := map[string]model.LinuxSystemdSetting{}
	for _, setting := range result.Settings {
		settings[setting.Key] = setting
	}
	if len(settings) != 2 || settings["User"].Values[0].Value != "late" || settings["User"].Values[0].Path != "/usr/lib/systemd/system/demo.service.d/30-late.conf" {
		t.Fatal(settings)
	}
	commands := settings["ExecStart"]
	if commands.Rule != "append_reset" || len(commands.Values) != 2 || commands.Values[0].Value != "/chosen" || commands.Values[1].Value != "/second" || len(commands.Resets) != 1 || commands.Resets[0].Line != 2 || commands.Values[0].Line != 3 {
		t.Fatal(commands)
	}
	if model.LinuxPersistenceInputDigest(snapshot) != before {
		t.Fatal("merge mutated raw input")
	}
	// Enumeration order is not source precedence, although the input binding is
	// intentionally order-sensitive to force revalidation after case rewrites.
	for left, right := 0, len(snapshot.LinuxArtifacts)-1; left < right; left, right = left+1, right-1 {
		snapshot.LinuxArtifacts[left], snapshot.LinuxArtifacts[right] = snapshot.LinuxArtifacts[right], snapshot.LinuxArtifacts[left]
	}
	again := mergeFixtureResult(t, snapshot)
	if !reflect.DeepEqual(result.Settings, again.Settings) || !reflect.DeepEqual(result.Sources, again.Sources) {
		t.Fatal("merge depends on input enumeration")
	}
}

func TestSystemdGeneratorAndSpecificDropinPriority(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/etc/systemd/system/demo.service", "[Service]\nUser=admin\n"),
		linuxConfigFixture("systemd", "/run/systemd/generator.early/demo.service", "[Service]\nUser=early\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/service.d/10.conf", "[Service]\nUser=typewide\n"),
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service.d/10.conf", "[Service]\nUser=specific\n"),
	)
	result := mergeFixtureResult(t, snapshot)
	if result.Status != "observed_subset" || result.Settings[0].Values[0].Value != "specific" || result.Sources[0].Path != "/run/systemd/generator.early/demo.service" {
		t.Fatal(result)
	}
}

func TestSystemdMergeUncertaintyNeverFallsBack(t *testing.T) {
	base := linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service", "[Service]\nExecStart=/vendor\n")
	for _, test := range []struct {
		name   string
		mutate func(*model.PersistenceSnapshot)
	}{
		{"unreadable higher", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service", ReadError: "denied"})
		}},
		{"unit mask", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service", Mode: "Lrwxrwxrwx", LinkTarget: "/dev/null"})
		}},
		{"unit alias", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service", Mode: "Lrwxrwxrwx", LinkTarget: "other.service"})
		}},
		{"empty unit", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, linuxConfigFixture("systemd", "/etc/systemd/system/demo.service", ""))
		}},
		{"lib ambiguity", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, linuxConfigFixture("systemd", "/lib/systemd/system/demo.service", "[Service]\nExecStart=/other\n"))
		}},
		{"duplicate source", func(s *model.PersistenceSnapshot) { s.LinuxArtifacts = append(s.LinuxArtifacts, base) }},
		{"partial source inventory", func(s *model.PersistenceSnapshot) { s.LinuxSources[0].Status = "partial" }},
		{"missing source inventory", func(s *model.PersistenceSnapshot) { s.LinuxSources = nil }},
		{"duplicate source inventory", func(s *model.PersistenceSnapshot) { s.LinuxSources = append(s.LinuxSources, s.LinuxSources[0]) }},
		{"contradictory inventory", func(s *model.PersistenceSnapshot) {
			for i := range s.LinuxSources {
				if s.LinuxSources[i].Path == "/usr/lib/systemd/system" {
					s.LinuxSources[i].Status = "missing"
				}
			}
		}},
		{"partial dropin", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, linuxConfigFixture("systemd", "/etc/systemd/system/demo.service.d/10.conf", "[bad\nExecStart=/wrong\n"))
		}},
		{"linked dropin directory", func(s *model.PersistenceSnapshot) {
			s.LinuxArtifacts = append(s.LinuxArtifacts, model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service.d", LinkTarget: "/somewhere", Mode: "Lrwxrwxrwx"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := systemdMergeFixture(base)
			test.mutate(&snapshot)
			result := mergeFixtureResult(t, snapshot)
			if result.Status != "blocked" || len(result.Settings) != 0 || len(result.Warnings) == 0 || result.Activation != "unknown" {
				t.Fatal("uncertainty produced settings", result)
			}
		})
	}
}

func TestSystemdDropinMasksAndUnsupportedProfiles(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service", "[Service]\nUser=base\n"),
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service.d/10.conf", "[Service]\nUser=wrong\n"),
		model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/demo.service.d/10.conf", LinkTarget: "/dev/null", Mode: "Lrwxrwxrwx"},
	)
	result := mergeFixtureResult(t, snapshot)
	if result.Status != "observed_subset" || result.Settings[0].Values[0].Value != "base" {
		t.Fatal(result)
	}
	masked := false
	for _, source := range result.Sources {
		if source.Decision == "masked_dropin" {
			masked = true
		}
	}
	if !masked {
		t.Fatal("mask evidence lost")
	}
	for _, name := range []string{"escaped\\x20.service", "@empty-prefix.service", "demo@a@b.service"} {
		s := systemdMergeFixture(linuxConfigFixture("systemd", "/etc/systemd/system/"+name, "[Service]\nUser=root\n"))
		r := mergeFixtureResult(t, s)
		if r.Status != "blocked" || len(r.Settings) > 0 {
			t.Fatal(r)
		}
	}
	// Drop-ins alone do not invent a base unit; user scope never mixes into system.
	s := systemdMergeFixture(linuxConfigFixture("systemd", "/etc/systemd/system/demo.service.d/10.conf", "[Service]\nUser=root\n"))
	if r := mergeFixtureResult(t, s); r.Status != "blocked" {
		t.Fatal(r)
	}
	s = systemdMergeFixture(linuxConfigFixture("systemd", "/etc/systemd/user/demo.service", "[Service]\nUser=root\n"))
	analysis := AnalyzePersistence(context.Background(), s, model.NetworkAnalysis{})
	if len(analysis.LinuxSystemdMerges) != 0 {
		t.Fatal("mixed user and system")
	}
}

func TestSystemdMergeBoundsAndCancellation(t *testing.T) {
	s := systemdMergeFixture(linuxConfigFixture("systemd", "/etc/systemd/system/demo.service", "[Service]\nUser=root\n"))
	configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), s.LinuxArtifacts)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, warnings := mergeObservedSystemd(ctx, s, configs)
	if len(results) != 0 || !strings.Contains(strings.Join(warnings, " "), "cancelled") {
		t.Fatal("cancel lost")
	}
	result := model.LinuxSystemdMerge{Unit: "demo.service", Status: "blocked"}
	index := map[string][]systemdCandidate{"demo.service": {{artifact: s.LinuxArtifacts[0], role: "unit"}}}
	parsed := map[string][]model.LinuxPersistenceConfig{s.LinuxArtifacts[0].Path: configs}
	records, bytesLeft, refs := 0, 100, 100
	mergeOneSystemd(context.Background(), &result, index, parsed, &records, &bytesLeft, &refs)
	if result.Status != "blocked" || len(result.Settings) != 0 {
		t.Fatal("record bound ignored")
	}
}

func FuzzSystemdObservedMerge(f *testing.F) {
	f.Add(uint8(0), "[Service]\nExecStart=\nExecStart=/bin/true\n")
	f.Add(uint8(1), "[bad\nUser=wrong\n")
	f.Add(uint8(2), "[Service]\nUser=last\n")
	f.Fuzz(func(t *testing.T, flags uint8, text string) {
		if len(text) > 32768 {
			t.Skip()
		}
		s := systemdMergeFixture(linuxConfigFixture("systemd", "/usr/lib/systemd/system/demo.service", "[Service]\nExecStart=/vendor\nUser=base\n"), linuxConfigFixture("systemd", "/etc/systemd/system/demo.service.d/10.conf", text))
		if flags&1 != 0 {
			s.LinuxSources[0].Status = "partial"
		}
		if flags&2 != 0 {
			s.LinuxArtifacts = append(s.LinuxArtifacts, linuxConfigFixture("systemd", "/lib/systemd/system/demo.service", "[Service]\nUser=ambiguous\n"))
		}
		if flags&4 != 0 {
			s.LinuxArtifacts[1].ReadError = "denied"
		}
		before := model.LinuxPersistenceInputDigest(s)
		configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), s.LinuxArtifacts)
		results, _ := mergeObservedSystemd(context.Background(), s, configs)
		if len(results) != 1 || results[0].Activation != "unknown" || results[0].InputDigest != before || model.LinuxPersistenceInputDigest(s) != before {
			t.Fatal("merge invariant")
		}
		if results[0].Status == "blocked" && len(results[0].Settings) > 0 {
			t.Fatal("blocked projection emitted settings")
		}
		if flags&7 != 0 && results[0].Status != "blocked" {
			t.Fatal("uncertain projection succeeded")
		}
	})
}
