package linux

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNativeLinuxLoginPermissionsAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	writeProcFixture(t, root, "var/log/auth.log", "private")
	if err := os.Chmod(filepath.Join(root, "var/log/auth.log"), 0000); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "var/log/secure"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := collectLinuxLogin(context.Background(), root, 1<<20, 2<<20)
	if err == nil {
		t.Fatal("special source silently accepted")
	}
	for _, artifact := range snapshot.LinuxArtifacts {
		if artifact.Path == "/var/log/secure" || artifact.Path == "/var/log/auth.log" && os.Geteuid() != 0 {
			if artifact.Status != "error" || artifact.Content != nil || artifact.SHA256 != "" || artifact.UID == nil || *artifact.UID != uint32(os.Geteuid()) {
				t.Fatal("unsafe source accepted or owner lost", artifact)
			}
		}
	}
}
