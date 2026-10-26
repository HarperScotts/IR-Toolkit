//go:build linux

package linux

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"ir-toolkit/internal/model"
)

var login1BootPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func login1BootID() (string, error) {
	root, err := os.OpenRoot("/proc/sys/kernel/random")
	if err != nil {
		return "", err
	}
	defer root.Close()
	data, err := readProcBounded(root, "boot_id", 256)
	id := strings.TrimSpace(string(data))
	if err != nil {
		return "", err
	}
	if !login1BootPattern.MatchString(id) {
		return "", fmt.Errorf("invalid collector kernel boot ID")
	}
	return id, nil
}

func collectPlatformLogin1(ctx context.Context) (model.LinuxLogin1Snapshot, error) {
	if ctx == nil || ctx.Err() != nil {
		return collectLogin1(ctx, runLogin1Command("/usr/bin/busctl"), "", "/usr/bin/busctl", login1Address)
	}
	boot, beforeErr := login1BootID()
	result, err := collectLogin1(ctx, runLogin1Command("/usr/bin/busctl"), boot, "/usr/bin/busctl", login1Address)
	after, afterErr := login1BootID()
	if beforeErr != nil || afterErr != nil || boot != after {
		contextErr := errors.Join(fmt.Errorf("collector kernel boot context unavailable or changed"), beforeErr, afterErr)
		result.Warnings = append(result.Warnings, contextErr.Error())
		if result.Status == "observed_subset" {
			result.Status = "partial"
		}
		err = errors.Join(err, contextErr)
	}
	return result, err
}
