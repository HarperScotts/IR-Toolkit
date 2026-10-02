//go:build windows

package windows

import (
	"context"
	"os"
	"os/user"
	"runtime"

	"ir-toolkit/internal/model"
)

type HostCollector struct{}

func (c *HostCollector) Name() string {
	return "windows_host"
}

func (c *HostCollector) Collect(
	ctx context.Context,
) (any, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()

	default:
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	currentUser := ""

	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}

	info := model.HostInfo{
		Hostname:     hostname,
		OS:           "windows",
		Architecture: runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		CurrentUser:  currentUser,
	}

	return info, nil
}
