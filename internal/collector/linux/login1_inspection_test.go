package linux

import (
	"context"
	"runtime"
	"testing"
)

func TestLogin1InspectionNilContext(t *testing.T) {
	_, err := InspectLogin1(nil)
	if err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestLogin1InspectionCancelledOrUnsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := InspectLogin1(ctx)
	if err == nil || r.OS != runtime.GOOS || r.Architecture != runtime.GOARCH {
		t.Fatal(r, err)
	}
	if runtime.GOOS != "linux" && (len(r.Snapshot.Calls) != 0 || r.Tool.Status != "not_exercised") {
		t.Fatal("unsupported platform attempted bus access", r)
	}
}
