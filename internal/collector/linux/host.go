package linux

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strings"

	"ir-toolkit/internal/model"
)

type HostCollector struct{}

func (c *HostCollector) Name() string {
	return "linux_host"
}

func (c *HostCollector) Collect(ctx context.Context) (any, error) {
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

	kernel := ""

	if data, err := os.ReadFile(
		"/proc/sys/kernel/osrelease",
	); err == nil {
		kernel = strings.TrimSpace(string(data))
	}

	info := model.HostInfo{
		Hostname:     hostname,
		OS:           "linux",
		Architecture: runtime.GOARCH,
		Kernel:       kernel,
		CPUCount:     runtime.NumCPU(),
		CurrentUser:  currentUser,
	}

	return info, nil
}
