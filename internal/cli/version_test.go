package cli

import (
	"testing"

	"ir-toolkit/internal/buildinfo"
)

func TestApplicationVersion(t *testing.T) {
	if rootCmd.Version != buildinfo.Version || buildinfo.Version != "0.3.0" {
		t.Fatalf("CLI/application version mismatch: %q / %q", rootCmd.Version, buildinfo.Version)
	}
}
