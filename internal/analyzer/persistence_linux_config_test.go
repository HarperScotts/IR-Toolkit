package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
)

func linuxConfigFixture(kind, path, text string) model.LinuxPersistenceArtifact {
	sum := sha256.Sum256([]byte(text))
	return model.LinuxPersistenceArtifact{Kind: kind, Path: path, Content: []byte(text), SHA256: fmt.Sprintf("%x", sum)}
}

func TestLinuxSystemdSourceLocalSyntax(t *testing.T) {
	text := "# unit\n[Service]\nExecStart=/bin/old\nExecStart=\nExecStart=/bin/echo one \\\n# ignored in continuation\n; also ignored\n two # literal\nEnvironment=NAME=\"a b\"\n[Install]\nWantedBy=multi-user.target\n"
	source := linuxConfigFixture("systemd", "/etc/systemd/system/X.service", text)
	before := bytes.Clone(source.Content)
	result := AnalyzePersistence(context.Background(), model.PersistenceSnapshot{LinuxArtifacts: []model.LinuxPersistenceArtifact{source}}, model.NetworkAnalysis{Processes: []model.ProcessNetworkAnalysis{{PID: 42, ProcessPath: "/bin/echo"}}})
	if len(result.LinuxConfigs) != 1 {
		t.Fatal(result)
	}
	config := result.LinuxConfigs[0]
	if config.Status != "observed_syntax" || config.Activation != "unknown" || len(config.Directives) != 5 || config.Directives[1].Value != "" || !config.Directives[1].EmptyAssignment || config.Directives[2].Line != 5 || config.Directives[2].EndLine != 8 || !strings.Contains(config.Directives[2].Value, "two # literal") || config.Directives[4].Section != "Install" {
		t.Fatalf("bad source-local syntax: %+v", config)
	}
	if len(result.Findings) != 0 || result.Statistics.LinuxDirectiveCount != 5 || result.Statistics.ServiceCount != 0 || !bytes.Equal(before, source.Content) {
		t.Fatal("parser invented semantics or mutated source", result)
	}
	// Preserve declarations from different files independently, with no merge.
	dropin := linuxConfigFixture("systemd", "/etc/systemd/system/X.service.d/override.conf", "[Service]\nExecStart=\nExecStart=/tmp/other\n")
	configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), []model.LinuxPersistenceArtifact{source, dropin})
	if len(configs) != 2 || len(configs[0].Directives) != 5 || len(configs[1].Directives) != 2 {
		t.Fatal("merged source configuration", configs)
	}
}

func TestLinuxCronOriginAndLiteralCommands(t *testing.T) {
	command := "echo  \"hello # literal\" \\%rest%stdin # command comment"
	sources := []model.LinuxPersistenceArtifact{
		linuxConfigFixture("cron", "/etc/cron.d/test", "SHELL = /bin/bash\nCRON_TZ=Asia/Shanghai\n*/5 0-23/2 * jan-mar mon,wed root "+command+"\n@reboot nobody /bin/true\n"),
		linuxConfigFixture("cron", "/var/spool/cron/crontabs/Alice", "PATH=\"/bin:/usr/bin\"  \n0 1 * * * /bin/echo  user\n"),
		linuxConfigFixture("cron", "/etc/cron.daily/script", "#!/bin/sh\necho should-not-be-parsed\n"),
		linuxConfigFixture("cron", "/etc/anacrontab", "1 5 daily command\n"),
	}
	configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), sources)
	if len(configs[0].CronEntries) != 2 || len(configs[0].Directives) != 2 || configs[0].CronEntries[0].CommandRaw != command || configs[0].CronEntries[0].DeclaredUser != "root" || configs[0].CronEntries[0].UserSource != "system_field" || configs[0].CronEntries[0].Line != 3 || configs[0].Status != "partial" {
		t.Fatal(configs[0])
	}
	user := configs[1].CronEntries[0]
	if user.DeclaredUser != "Alice" || user.UserSource != "spool_filename" || user.CommandRaw != "/bin/echo  user" || configs[1].Directives[0].Value != "\"/bin:/usr/bin\"  " {
		t.Fatal(configs[1])
	}
	if configs[2].Status != "skipped" || configs[3].Status != "skipped" || len(configs[2].CronEntries) != 0 {
		t.Fatal("script/anacron misinterpreted", configs)
	}
	for _, config := range configs {
		if config.Activation != "unknown" {
			t.Fatal("inferred activation")
		}
	}
}

func TestLinuxConfigFailuresAndBounds(t *testing.T) {
	for _, text := range []string{"[Service\nExecStart=wrong\n", "[Service]\nExecStart=unterminated\\", "outside=section\n", "[Service]\ninvalid line\n"} {
		configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), []model.LinuxPersistenceArtifact{linuxConfigFixture("systemd", "/unit.service", text)})
		if configs[0].Status != "partial" || len(configs[0].Warnings) == 0 {
			t.Fatal("syntax failure hidden", configs)
		}
	}
	for _, text := range []string{"70 * * * * root /bad\n", "* * * * root\n", "@unknown root /bad\n", "* * * * * root /bin/true"} {
		configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), []model.LinuxPersistenceArtifact{linuxConfigFixture("cron", "/etc/crontab", text)})
		if configs[0].Status != "partial" {
			t.Fatal("cron failure hidden", configs)
		}
	}
	for _, schedule := range []string{"0 0 * * *", "*/2 0-23/2 1,5 jan,feb mon-fri", "@reboot"} {
		if !validCronSchedule(strings.Fields(schedule)) {
			t.Fatal(schedule)
		}
	}
	for _, schedule := range []string{"60 * * * *", "* 24 * * *", "*/0 * * * *", "* * 0 * *", "* * * nope *", "* * * * 8", "* * * * fri-mon", "1/2 * * * *", "* * * * ~"} {
		if validCronSchedule(strings.Fields(schedule)) {
			t.Fatal(schedule)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*model.LinuxPersistenceArtifact)
	}{
		{"hash", func(a *model.LinuxPersistenceArtifact) { a.SHA256 = "wrong" }},
		{"missing hash", func(a *model.LinuxPersistenceArtifact) { a.SHA256 = "" }},
		{"read error", func(a *model.LinuxPersistenceArtifact) { a.ReadError = "denied" }},
		{"link", func(a *model.LinuxPersistenceArtifact) { a.LinkTarget = "/dev/null" }},
		{"binary", func(a *model.LinuxPersistenceArtifact) { a.Content = []byte{0xff, 0} }},
		{"bytes", func(a *model.LinuxPersistenceArtifact) { a.Content = make([]byte, (1<<20)+1) }},
		{"lines", func(a *model.LinuxPersistenceArtifact) { a.Content = bytes.Repeat([]byte{'\n'}, 65537) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := linuxConfigFixture("systemd", "/unit.service", "[Service]\nExecStart=/bin/true\n")
			test.mutate(&a)
			configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), []model.LinuxPersistenceArtifact{a})
			if configs[0].Status != "skipped" || len(configs[0].Directives) != 0 {
				t.Fatal(configs)
			}
		})
	}
	config := model.LinuxPersistenceConfig{Status: "observed_syntax"}
	parseSystemdConfig(context.Background(), []byte("[Service]\nA=1\nB=2\n"), &config, 1)
	if len(config.Directives) != 1 || config.Status != "partial" {
		t.Fatal("record bound ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	configs, warnings := analyzeLinuxPersistenceConfigs(ctx, []model.LinuxPersistenceArtifact{linuxConfigFixture("cron", "/etc/crontab", "@reboot root /bin/true\n")})
	if len(configs) != 0 || !strings.Contains(strings.Join(warnings, " "), "cancelled") {
		t.Fatal("cancel hidden")
	}
}

func FuzzLinuxPersistenceConfig(f *testing.F) {
	for _, seed := range []string{"[Service]\nExecStart=\n", "[", "@reboot root /bin/true\n", "# comment\\\n[Service]\nA=x", "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 1<<20 {
			t.Skip()
		}
		for _, kind := range []string{"systemd", "cron"} {
			source := linuxConfigFixture(kind, "/etc/crontab", text)
			before := bytes.Clone(source.Content)
			configs, _ := analyzeLinuxPersistenceConfigs(context.Background(), []model.LinuxPersistenceArtifact{source})
			if len(configs) != 1 || configs[0].Activation != "unknown" || len(configs[0].Directives)+len(configs[0].CronEntries) > 4096 || !reflect.DeepEqual(before, source.Content) {
				t.Fatal("parser invariant")
			}
		}
	})
}
