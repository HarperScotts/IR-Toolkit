//go:build linux && login1integration

package linux

import (
	"bufio"
	"bytes"
	"context"
	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func login1StartPrivatePeer(t *testing.T, executable string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	command := exec.CommandContext(ctx, executable, args...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	command.Stderr = &diagnostic
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); _ = command.Wait() })
	ready := make(chan error, 1)
	go func() { _, err := bufio.NewReader(stdout).ReadString('\n'); ready <- err }()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("private peer failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestLogin1PrivateBusIntegration(t *testing.T) {
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "autolaunch:")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "autolaunch:")
	t.Setenv("PATH", "/untrusted-executable-path")
	fixture := os.Getenv("IR_LOGIN1_TEST_SERVICE")
	if fixture == "" {
		t.Fatal("integration tag requires explicitly built IR_LOGIN1_TEST_SERVICE")
	}
	for _, mode := range []string{"live", "empty", "deny", "vanish"} {
		t.Run(mode, func(t *testing.T) {
			address := "unix:path=" + filepath.Join(t.TempDir(), "bus")
			login1StartPrivatePeer(t, "/usr/bin/dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1", "--address="+address)
			absent, err := collectLogin1(context.Background(), runLogin1Command("/usr/bin/busctl"), "private-fixture", "/usr/bin/busctl", address)
			if err == nil || absent.Status != "error" || len(absent.Calls) != 2 || absent.ServiceOwner != "" {
				t.Fatalf("absent service: %+v %v", absent, err)
			}
			login1StartPrivatePeer(t, fixture, address, mode)
			r, err := collectLogin1(context.Background(), runLogin1Command("/usr/bin/busctl"), "private-fixture", "/usr/bin/busctl", address)
			a := analyzer.AnalyzeLogin(context.Background(), model.LoginSnapshot{LinuxLogin1: &r}, model.NetworkAnalysis{}).LinuxLogin1
			if a == nil || a.Status == "skipped" {
				t.Fatalf("private-bus response not analyzable: %+v", a)
			}
			if mode == "deny" || mode == "vanish" {
				if a.Status != "partial" || len(a.Observations) != 1 || a.Observations[0].Properties.Active != nil {
					t.Fatal("failed call became known", a)
				}
				if err == nil || r.Status != "partial" || len(r.Sessions) != 1 || r.Calls[3].Status != "error" || len(r.Calls[3].Stderr) == 0 {
					t.Fatalf("failed properties: %+v %v", r, err)
				}
				return
			}
			if err != nil || r.Status != "observed_subset" || r.BusID == "" || !strings.HasPrefix(r.ServiceOwner, ":") {
				t.Fatalf("read-only roundtrip: %+v %v", r, err)
			}
			if mode == "empty" {
				if len(a.Observations) != 0 || a.Status != "observed_subset" {
					t.Fatal(a)
				}
				if len(r.Sessions) != 0 {
					t.Fatal(r.Sessions)
				}
				return
			}
			if len(r.Sessions) != 1 || r.Sessions[0].ReportedUser != "Alice" || !bytes.Contains(r.Calls[3].Content, []byte(`"data":false`)) || !bytes.Contains(r.Calls[3].Content, []byte(`"Leader"`)) {
				t.Fatalf("raw property fidelity: %+v", r)
			}
			if len(a.Observations) != 1 || a.Observations[0].Properties.Active == nil || *a.Observations[0].Properties.Active || a.Observations[0].Properties.Leader == nil || *a.Observations[0].Properties.Leader != 42 {
				t.Fatal("native false/PID claim lost", a)
			}
		})
	}
}

func TestLogin1NativeCommandBoundaries(t *testing.T) {
	root := t.TempDir()
	script := filepath.Join(root, "helper")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf 123456789\nprintf diagnostic >&2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	content, diagnostic, err := runLogin1Command(script)(context.Background(), nil, 3)
	if err == nil || content != nil || string(diagnostic) != "diagnostic" {
		t.Fatal(content, string(diagnostic), err)
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err = runLogin1Command(script)(ctx, nil, 3)
	if err == nil || time.Since(started) > time.Second {
		t.Fatal("command cancellation unbounded", err)
	}
}
