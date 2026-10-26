package cli

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	localstore "ir-toolkit/internal/store/local"
	"ir-toolkit/internal/testutil"
)

func TestAnalyzePlatformWindowsEventRequirement(t *testing.T) {
	for _, test := range []struct {
		name, platform     string
		corrupt, wantError bool
	}{
		{"linux missing", "linux", false, false},
		{"linux malformed", "linux", true, true},
		{"windows missing", "windows", false, true},
		{"legacy missing", "", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			cronContent := []byte("@reboot root /bin/true\n")
			cronHash := sha256.Sum256(cronContent)
			unitContent := []byte("[Service]\nExecStart=/bin/worker %i %I\n")
			unitHash := sha256.Sum256(unitContent)
			dropinContent := []byte("[Service]\nUser=nobody\n")
			dropinHash := sha256.Sum256(dropinContent)
			loginContent := []byte("2026-10-16T12:00:00Z host sshd[42]: Accepted publickey for alice from 192.0.2.1 port 22 ssh2\n")
			loginHash := sha256.Sum256(loginContent)
			login1 := testutil.Login1Snapshot()
			persistence := model.PersistenceSnapshot{Warnings: []string{"persistence unavailable fixture"}, LinuxArtifacts: []model.LinuxPersistenceArtifact{
				{Kind: "cron", Path: "/etc/crontab", Content: cronContent, SHA256: fmt.Sprintf("%x", cronHash)},
				{Kind: "systemd", Path: "/usr/lib/systemd/system/worker@.service", Content: unitContent, SHA256: fmt.Sprintf("%x", unitHash)},
				{Kind: "systemd", Path: "/etc/systemd/system/worker@east.service.d/10.conf", Content: dropinContent, SHA256: fmt.Sprintf("%x", dropinHash)},
			}}
			for _, name := range []string{"/etc/systemd/system.control", "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator.early", "/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system", "/run/systemd/system.attached", "/run/systemd/generator", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system", "/run/systemd/generator.late"} {
				persistence.LinuxSources = append(persistence.LinuxSources, model.LinuxPersistenceSource{Path: name, Kind: "systemd", Status: "observed"})
			}
			for path, value := range map[string]any{
				"host/host.json":                 model.HostInfo{OS: test.platform},
				"process/processes.json":         []model.Process{},
				"network/network.json":           model.NetworkSnapshot{},
				"capabilities/capabilities.json": model.AuditCapabilitySnapshot{},
				"login/login.json":               model.LoginSnapshot{LinuxLogin1: &login1, Warnings: []string{"login unavailable fixture"}, LinuxArtifacts: []model.LinuxLoginArtifact{{Path: "/var/log/auth.log", Kind: "auth_log", Status: "observed", Content: loginContent, SHA256: fmt.Sprintf("%x", loginHash)}}},
				"files/files.json":               model.FileTriageSnapshot{Warnings: []string{"files unavailable fixture"}},
				"persistence/persistence.json":   persistence,
				"events/process_events.json":     model.ProcessEventSnapshot{Warnings: []string{"process history unavailable fixture"}},
				"events/powershell_events.json":  model.PowerShellEventSnapshot{Warnings: []string{"PowerShell unavailable fixture"}},
				"manifest.json":                  model.Manifest{CaseID: "linux-fixture"},
			} {
				writeCentralJSON(t, root, path, value)
			}
			if test.corrupt {
				if err := os.WriteFile(filepath.Join(root, "events", "windows_events.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			err := runAnalyze(cmd, []string{root})
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %v", err, test.wantError)
			}
			if test.wantError {
				return
			}
			var report model.CaseReport
			readTimelineTestJSON(t, filepath.Join(root, "analysis", "report.json"), &report)
			gaps := strings.Join(report.EvidenceGaps, " ")
			if !strings.Contains(gaps, "log-reported OpenSSH") {
				t.Fatal("Linux login analysis gaps lost")
			}
			var nativeLogin model.LoginAnalysis
			readTimelineTestJSON(t, filepath.Join(root, "analysis/login_analysis.json"), &nativeLogin)
			if len(nativeLogin.LinuxRecords) != 1 || len(nativeLogin.Sessions) != 0 || len(nativeLogin.Findings) != 0 {
				t.Fatal("native authentication claim lost or became session", nativeLogin)
			}
			if nativeLogin.LinuxLogin1 == nil || len(nativeLogin.LinuxLogin1.Observations) != 2 || nativeLogin.LinuxLogin1.Observations[0].Properties.Active == nil || *nativeLogin.LinuxLogin1.Observations[0].Properties.Active || !strings.Contains(gaps, "Linux login1 analysis:") {
				t.Fatal("login1 analysis/uncertainty lost in persisted CLI output")
			}
			if !strings.Contains(gaps, "file-local syntax only") {
				t.Fatal("Linux parser coverage warning lost")
			}
			var persistenceAnalysis model.PersistenceAnalysis
			readTimelineTestJSON(t, filepath.Join(root, "analysis/persistence_analysis.json"), &persistenceAnalysis)
			if len(persistenceAnalysis.LinuxConfigs) != 3 || persistenceAnalysis.Statistics.LinuxCronEntryCount != 1 || len(persistenceAnalysis.Findings) != 0 {
				t.Fatal("Linux parser output missing or invented findings", persistenceAnalysis)
			}
			foundInstance := false
			for _, merge := range persistenceAnalysis.LinuxSystemdMerges {
				if merge.Unit == "worker@east.service" {
					foundInstance = merge.Profile == "observed-system-service-v2" && merge.NameKind == "instance" && merge.BaseLookup == "template_fallback" && merge.Status == "observed_subset" && merge.Activation == "unknown"
				}
			}
			if !foundInstance {
				t.Fatal("CLI lost conservative template fallback", persistenceAnalysis.LinuxSystemdMerges)
			}
			if report.Host.OS != "linux" || !strings.Contains(report.Summary.Statement, fmt.Sprintf("%d known gap(s)", len(report.EvidenceGaps))) {
				t.Fatal("report platform or warning count lost", report.Summary.Statement)
			}
			for _, want := range []string{"login unavailable fixture", "files unavailable fixture", "persistence unavailable fixture", "process history unavailable fixture", "PowerShell unavailable fixture", "native Linux historical event collection is not implemented"} {
				if !strings.Contains(gaps, want) {
					t.Fatalf("report lost gap %q: %s", want, gaps)
				}
			}
			if _, err := os.Stat(filepath.Join(root, "events", "windows_events.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("synthesized Windows evidence: %v", err)
			}
		})
	}
}

func TestNativeLinuxCollectAnalyze(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires real Linux procfs")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	previousOutput, previousFull := outputDir, fullMode
	previousSince, previousUntil, previousLast := collectSince, collectUntil, collectLast
	t.Cleanup(func() {
		outputDir, fullMode = previousOutput, previousFull
		collectSince, collectUntil, collectLast = previousSince, previousUntil, previousLast
	})
	outputDir, fullMode = filepath.Join(t.TempDir(), "case"), false
	collectSince, collectUntil, collectLast = "", "", ""
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := runCollect(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if err := runAnalyze(cmd, []string{outputDir}); err != nil {
		t.Fatal(err)
	}
	var report model.CaseReport
	readTimelineTestJSON(t, filepath.Join(outputDir, "analysis", "report.json"), &report)
	if !strings.Contains(strings.Join(report.EvidenceGaps, " "), "Linux login scope:") {
		t.Fatal("incomplete native collection lost from report")
	}
	var login model.LoginSnapshot
	readTimelineTestJSON(t, filepath.Join(outputDir, "login", "login.json"), &login)
	if login.LinuxLogin1 == nil || login.LinuxLogin1.Status == "" || login.LinuxLogin1.StartedAt.IsZero() || login.LinuxLogin1.CompletedAt.Before(login.LinuxLogin1.StartedAt) {
		t.Fatal("native login1 observation/status lost from raw snapshot")
	}
	if !strings.Contains(strings.Join(report.EvidenceGaps, " "), "Linux login1 scope:") {
		t.Fatal("login1 uncertainty lost from report")
	}
	var persistence model.PersistenceSnapshot
	readTimelineTestJSON(t, filepath.Join(outputDir, "persistence", "persistence.json"), &persistence)
	if len(persistence.LinuxSources) == 0 {
		t.Fatal("Linux persistence source inventory missing")
	}
	persistenceItems, err := localstore.New(outputDir).QueryPersistence(store.PersistenceQueryOptions{})
	if err != nil || persistenceItems.Total != uint32(len(persistence.LinuxArtifacts)) {
		t.Fatal("native persistence inventory lost from Store", err)
	}
	if !strings.Contains(strings.Join(report.EvidenceGaps, " "), "effective unit/drop-in/cron parsing") {
		t.Fatal("persistence analysis limitations lost")
	}
	connections, err := localstore.New(outputDir).QueryNetwork(store.NetworkQueryOptions{PID: uint32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	tcpFound, udpFound := false, false
	for _, item := range connections.Items {
		if item.External {
			t.Fatal("own loopback marked external")
		}
		if item.Protocol == "TCP" && item.LocalPort == uint32(listener.Addr().(*net.TCPAddr).Port) {
			tcpFound = true
		}
		if item.Protocol == "UDP" && item.LocalPort == uint32(packet.LocalAddr().(*net.UDPAddr).Port) {
			udpFound = true
		}
	}
	if !tcpFound || !udpFound {
		t.Fatal("collect/analyze/Store lost native loopback sockets")
	}
	var processes []model.Process
	readTimelineTestJSON(t, filepath.Join(outputDir, "process", "processes.json"), &processes)
	for _, process := range processes {
		if process.PID == uint32(os.Getpid()) && process.ProcessInstanceID != "" {
			return
		}
	}
	t.Fatal("native collection lost its own process identity")
}
