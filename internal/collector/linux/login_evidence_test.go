package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestLinuxLoginRawCollection(t *testing.T) {
	root := t.TempDir()
	text := "Oct 16 12:00:00 host sshd[1]: Accepted password for alice from 127.0.0.1 port 22 ssh2\n"
	writeProcFixture(t, root, "var/log/auth.log", text)
	writeProcFixture(t, root, "run/utmp", "\x00\xff\x00\x01")
	writeProcFixture(t, root, "var/log/wtmp", "")
	linkProcFixture(t, root, "var/log/secure", "/never-follow-this")
	snapshot, err := collectLinuxLogin(context.Background(), root, 1<<20, 2<<20)
	if err == nil || len(snapshot.LinuxArtifacts) != 7 || len(snapshot.Events) != 0 || len(snapshot.Sessions) != 0 {
		t.Fatal("lost native scope or errors", snapshot, err)
	}
	for _, artifact := range snapshot.LinuxArtifacts {
		switch artifact.Path {
		case "/var/log/auth.log":
			sum := sha256.Sum256([]byte(text))
			if artifact.Status != "observed" || artifact.SHA256 != fmt.Sprintf("%x", sum) || !bytes.Equal(artifact.Content, []byte(text)) {
				t.Fatal(artifact)
			}
		case "/run/utmp":
			if !bytes.Equal(artifact.Content, []byte{0, 255, 0, 1}) || artifact.Kind != "current_accounting" {
				t.Fatal("binary bytes reinterpreted", artifact)
			}
		case "/var/log/wtmp":
			if artifact.Status != "observed" || artifact.SHA256 == "" || len(artifact.Content) != 0 {
				t.Fatal("empty source conflated with missing", artifact)
			}
		case "/var/log/secure":
			if artifact.Status != "error" || artifact.LinkTarget != "/never-follow-this" || artifact.Content != nil || artifact.SHA256 != "" {
				t.Fatal("link followed", artifact)
			}
		default:
			if artifact.Status != "missing" {
				t.Fatal(artifact)
			}
		}
	}
}

func TestLinuxLoginCollectionLimitsAndCancel(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, "var/log/auth.log", "too much")
	snapshot, err := collectLinuxLogin(context.Background(), root, 1, 1)
	if err == nil || snapshot.LinuxArtifacts[0].Status != "error" || snapshot.LinuxArtifacts[0].Content != nil || snapshot.LinuxArtifacts[0].SHA256 != "" {
		t.Fatal("limit silently truncated", snapshot, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, err = collectLinuxLogin(ctx, root, 1<<20, 2<<20)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancel identity lost", err)
	}
	for _, artifact := range snapshot.LinuxArtifacts {
		if artifact.Status != "not_scanned" || artifact.Content != nil {
			t.Fatal(artifact)
		}
	}
}
