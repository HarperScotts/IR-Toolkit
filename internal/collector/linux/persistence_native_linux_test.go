package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativePersistenceSafeOpenAndPermissions(t *testing.T) {
	rootPath := t.TempDir()
	writeProcFixture(t, rootPath, "etc/cron.d/readable", "* * * * * root /bin/true\n")
	writeProcFixture(t, rootPath, "etc/cron.d/denied", "unreadable")
	if err := os.Chmod(filepath.Join(rootPath, "etc/cron.d/denied"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(rootPath, "etc/cron.d/pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	linkProcFixture(t, rootPath, "etc/cron.d/link", "readable")
	snapshot, err := collectPersistence(context.Background(), rootPath, fixturePersistenceLimits())
	if err == nil {
		t.Fatal("special file must report incomplete collection")
	}
	seen := map[string]bool{}
	for _, artifact := range snapshot.LinuxArtifacts {
		name := filepath.Base(artifact.Path)
		seen[name] = true
		if artifact.UID == nil || *artifact.UID != uint32(os.Geteuid()) || artifact.GID == nil {
			t.Fatalf("owner metadata lost: %+v", artifact)
		}
		switch name {
		case "pipe":
			if artifact.ReadError == "" || artifact.Content != nil || artifact.SHA256 != "" {
				t.Fatal("FIFO treated as file")
			}
		case "denied":
			if os.Geteuid() != 0 && (artifact.ReadError == "" || artifact.Content != nil || artifact.SHA256 != "") {
				t.Fatal("denied read presented as successful")
			}
		case "readable":
			if artifact.ReadError != "" || artifact.SHA256 == "" {
				t.Fatal("safe regular open failed", artifact.ReadError)
			}
		}
	}
	if len(seen) != 4 {
		t.Fatal("missing fixture artifacts", seen)
	}
	root, err := os.OpenRoot(filepath.Join(rootPath, "etc/cron.d"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"pipe", "link"} {
		if file, err := openPersistenceFile(root, name); err == nil {
			file.Close()
			t.Fatalf("unsafe candidate opened: %s", name)
		}
	}
}
