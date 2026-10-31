//go:build darwin || linux

package analysiscommit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestNativeVerificationSpecialFileAndDenied(t *testing.T) {
	root, _ := diskFixture(t, false)
	path := filepath.Join(root, "analysis/report.txt")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDirectory(context.Background(), root, DefaultLimits()); err == nil {
		t.Fatal("FIFO accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := VerifyDirectory(context.Background(), root, DefaultLimits()); !errors.Is(err, os.ErrPermission) {
			t.Fatal("denied file accepted or permission identity lost", err)
		}
	}
}
