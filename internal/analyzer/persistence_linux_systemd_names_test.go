package analyzer

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
)

func systemdMergeForUnit(t *testing.T, snapshot model.PersistenceSnapshot, unit string) model.LinuxSystemdMerge {
	t.Helper()
	analysis := AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	if len(analysis.Findings) > 0 {
		t.Fatal("name resolution invented findings")
	}
	for _, result := range analysis.LinuxSystemdMerges {
		if result.Unit == unit {
			return result
		}
	}
	t.Fatalf("missing unit %s: %+v", unit, analysis.LinuxSystemdMerges)
	return model.LinuxSystemdMerge{}
}

func systemdSettingValue(t *testing.T, result model.LinuxSystemdMerge, key string) string {
	t.Helper()
	for _, setting := range result.Settings {
		if setting.Key == key && len(setting.Values) == 1 {
			return setting.Values[0].Value
		}
	}
	t.Fatalf("missing single value %s: %+v", key, result)
	return ""
}

func TestSystemdDropinNameExpansion(t *testing.T) {
	for _, test := range []struct {
		name string
		want []string
	}{
		{"foo-bar-baz.service", []string{"foo-bar-baz.service", "foo-bar-.service", "foo-.service"}},
		{"foo-bar-.service", []string{"foo-bar-.service", "foo-.service"}},
		{"-foo.service", []string{"-foo.service"}},
		{"foo--bar.service", []string{"foo--bar.service", "foo--.service", "foo-.service"}},
		{"worker@us-east.service", []string{"worker@us-east.service", "worker@.service"}},
		{"foo-bar@a-b.service", []string{"foo-bar@a-b.service", "foo-bar@.service", "foo-.service", "foo-@a-b.service", "foo-@.service"}},
		{"foo-bar@.service", []string{"foo-bar@.service", "foo-.service"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := observedSystemdDropinNames(test.name)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatal(got, err)
			}
		})
	}
	for _, name := range []string{"@x.service", "foo@a@b.service", "foo\\x2dbar.service", "foo@x/evil.service", "foo@x%.service", strings.Repeat("a", 248) + ".service"} {
		if _, err := parseObservedServiceName(name); err == nil {
			t.Fatal("unsupported name accepted", name)
		}
	}
	if _, err := observedSystemdDropinNames(strings.Repeat("a-", 70) + "z.service"); err == nil {
		t.Fatal("unbounded hierarchy expansion")
	}
}

func TestSystemdDashHierarchyPrecedence(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/foo-bar-baz.service", "[Service]\nUser=base\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/service.d/10.conf", "[Service]\nUser=type\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-.service.d/10.conf", "[Service]\nUser=broad\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-bar-.service.d/10.conf", "[Service]\nUser=near\n"),
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/foo-bar-baz.service.d/10.conf", "[Service]\nUser=vendor-exact\n"),
	)
	result := systemdMergeForUnit(t, snapshot, "foo-bar-baz.service")
	if result.Status != "observed_subset" || result.Profile != "observed-system-service-v2" || systemdSettingValue(t, result, "User") != "near" {
		t.Fatal("source rank must precede hierarchy rank", result)
	}
	snapshot.LinuxArtifacts = append(snapshot.LinuxArtifacts, linuxConfigFixture("systemd", "/etc/systemd/system/foo-bar-baz.service.d/10.conf", "[Service]\nUser=exact\n"))
	result = systemdMergeForUnit(t, snapshot, "foo-bar-baz.service")
	if systemdSettingValue(t, result, "User") != "exact" {
		t.Fatal("same-root specificity ignored", result)
	}
	analysis := AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	if len(analysis.LinuxSystemdMerges) != 1 {
		t.Fatal("hierarchy directory invented base units", analysis.LinuxSystemdMerges)
	}
}

func TestSystemdTemplateFallbackAndDefinition(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/worker@.service", "[Service]\nExecStart=/bin/worker %i %I\nUser=template\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/worker@.service.d/10.conf", "[Service]\nUser=template-override\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/worker@east.service.d/10.conf", "[Service]\nUser=instance\n"),
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/worker@east.service.d/20.conf", "[Service]\nWorkingDirectory=/srv/%i\n"),
	)
	instance := systemdMergeForUnit(t, snapshot, "worker@east.service")
	if instance.Status != "observed_subset" || instance.NameKind != "instance" || instance.Template != "worker@.service" || instance.Instance != "east" || instance.BaseLookup != "template_fallback" || instance.Activation != "unknown" || systemdSettingValue(t, instance, "ExecStart") != "/bin/worker %i %I" || systemdSettingValue(t, instance, "User") != "instance" || systemdSettingValue(t, instance, "WorkingDirectory") != "/srv/%i" {
		t.Fatal(instance)
	}
	definition := systemdMergeForUnit(t, snapshot, "worker@.service")
	if definition.NameKind != "template_definition" || definition.Instance != "" || definition.BaseLookup != "template_definition" || systemdSettingValue(t, definition, "User") != "template-override" {
		t.Fatal(definition)
	}
	// Exact instances are searched across all roots before considering templates.
	snapshot.LinuxArtifacts = append(snapshot.LinuxArtifacts, linuxConfigFixture("systemd", "/run/systemd/system/worker@.service", "[Service]\nExecStart=/higher-template\n"), linuxConfigFixture("systemd", "/usr/lib/systemd/system/worker@east.service", "[Service]\nExecStart=/exact-instance\n"))
	instance = systemdMergeForUnit(t, snapshot, "worker@east.service")
	if instance.BaseLookup != "exact" || systemdSettingValue(t, instance, "ExecStart") != "/exact-instance" {
		t.Fatal("template priority displaced exact instance", instance)
	}
}

func TestSystemdInstanceFailureDoesNotUseTemplate(t *testing.T) {
	for _, test := range []struct {
		name  string
		exact model.LinuxPersistenceArtifact
	}{
		{"read error", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/job@one.service", ReadError: "denied"}},
		{"alias", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/job@one.service", Mode: "Lrwxrwxrwx", LinkTarget: "job@.service"}},
		{"mask", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/job@one.service", Mode: "Lrwxrwxrwx", LinkTarget: "/dev/null"}},
		{"empty", linuxConfigFixture("systemd", "/etc/systemd/system/job@one.service", "")},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot := systemdMergeFixture(linuxConfigFixture("systemd", "/usr/lib/systemd/system/job@.service", "[Service]\nExecStart=/template\n"), test.exact)
			result := systemdMergeForUnit(t, snapshot, "job@one.service")
			if result.Status != "blocked" || len(result.Settings) != 0 || result.BaseLookup != "exact" {
				t.Fatal("failed exact lookup fell back", result)
			}
		})
	}
	snapshot := systemdMergeFixture(linuxConfigFixture("systemd", "/usr/lib/systemd/system/job@.service", "[Service]\nExecStart=/template\n"))
	analysis := AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	if len(analysis.LinuxSystemdMerges) != 1 || analysis.LinuxSystemdMerges[0].NameKind != "template_definition" {
		t.Fatal("template spawned implicit instances", analysis.LinuxSystemdMerges)
	}
}

func TestSystemdHierarchyAndTemplateFailureBlocks(t *testing.T) {
	for _, test := range []struct {
		name string
		bad  model.LinuxPersistenceArtifact
		unit string
	}{
		{"hierarchy directory link", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/foo-.service.d", Mode: "Lrwxrwxrwx", LinkTarget: "elsewhere"}, "foo-bar.service"},
		{"template directory link", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/worker@.service.d", Mode: "Lrwxrwxrwx", LinkTarget: "elsewhere"}, "worker@east.service"},
		{"unreadable selected template", model.LinuxPersistenceArtifact{Kind: "systemd", Path: "/etc/systemd/system/worker@.service", ReadError: "denied"}, "worker@east.service"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := systemdMergeFixture(linuxConfigFixture("systemd", "/usr/lib/systemd/system/foo-bar.service", "[Service]\nUser=base\n"), linuxConfigFixture("systemd", "/usr/lib/systemd/system/worker@.service", "[Service]\nUser=base\n"), linuxConfigFixture("systemd", "/etc/systemd/system/worker@east.service.d/10.conf", "[Service]\nGroup=instance\n"), test.bad)
			r := systemdMergeForUnit(t, s, test.unit)
			if r.Status != "blocked" || len(r.Settings) != 0 {
				t.Fatal("uncertainty emitted settings", r)
			}
		})
	}
}

func TestSystemdHierarchicalTemplateDropins(t *testing.T) {
	snapshot := systemdMergeFixture(
		linuxConfigFixture("systemd", "/usr/lib/systemd/system/foo-bar@.service", "[Service]\nUser=base\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-bar@x-y.service.d/10.conf", "[Service]\nGroup=instance\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-bar@.service.d/10.conf", "[Service]\nGroup=template\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-.service.d/20.conf", "[Service]\nUser=generic-chain\n"),
		linuxConfigFixture("systemd", "/etc/systemd/system/foo-@x-y.service.d/20.conf", "[Service]\nUser=instance-chain\n"),
	)
	result := systemdMergeForUnit(t, snapshot, "foo-bar@x-y.service")
	if result.Status != "observed_subset" || systemdSettingValue(t, result, "Group") != "instance" || systemdSettingValue(t, result, "User") != "generic-chain" {
		t.Fatal("upstream recursive name order lost", result)
	}
	// A higher-priority template drop-in wins a same-name vendor instance drop-in.
	snapshot = systemdMergeFixture(linuxConfigFixture("systemd", "/usr/lib/systemd/system/job@.service", "[Service]\nUser=base\n"), linuxConfigFixture("systemd", "/etc/systemd/system/job@.service.d/10.conf", "[Service]\nUser=admin-template\n"), linuxConfigFixture("systemd", "/usr/lib/systemd/system/job@one.service.d/10.conf", "[Service]\nUser=vendor-instance\n"))
	result = systemdMergeForUnit(t, snapshot, "job@one.service")
	if systemdSettingValue(t, result, "User") != "admin-template" {
		t.Fatal(result)
	}
}

func FuzzSystemdDropinNames(f *testing.F) {
	for _, name := range []string{"foo-bar@a-b.service", "foo--.service", "demo@.service", "a.service", "\\x20.service", ""} {
		f.Add(name)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 1024 {
			t.Skip()
		}
		names, err := observedSystemdDropinNames(name)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		if len(names) == 0 || len(names) > 64 || names[0] != name {
			t.Fatal("expansion bounds")
		}
		for _, candidate := range names {
			if seen[candidate] {
				t.Fatal("duplicate expansion")
			}
			seen[candidate] = true
			if _, err := parseObservedServiceName(candidate); err != nil {
				t.Fatal("invalid derived name", candidate)
			}
		}
	})
}
