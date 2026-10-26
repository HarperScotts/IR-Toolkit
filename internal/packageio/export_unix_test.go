//go:build darwin || linux

package packageio

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"
)

func TestExportCaseRejectsFIFO(t *testing.T) {
	root, _ := exportFixture(t)
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := ExportCase(context.Background(), root, "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidSource) || output.Len() != 0 {
		t.Fatalf("FIFO: %v", err)
	}
}
