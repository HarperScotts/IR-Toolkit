//go:build !linux

package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

func collectPlatformLogin1(ctx context.Context) (model.LinuxLogin1Snapshot, error) {
	return model.LinuxLogin1Snapshot{Status: "unsupported", Warnings: []string{"Linux login1 source is not available on this platform."}}, fmt.Errorf("login1 requires Linux")
}
