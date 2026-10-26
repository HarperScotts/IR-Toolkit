package linux

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"ir-toolkit/internal/model"
)

// InspectLogin1 uses exactly the production login1 transport. There is no test
// address, executable override or environment switch in the public entrypoint.
// It does not collect auth logs, proc process lists or accounting files.
func InspectLogin1(ctx context.Context) (model.LinuxLogin1Inspection, error) {
	result := model.LinuxLogin1Inspection{OS: runtime.GOOS, Architecture: runtime.GOARCH, EffectiveUID: os.Geteuid(), Tool: model.LinuxLogin1ToolProbe{Executable: "/usr/bin/busctl", Arguments: []string{"--version"}, Status: "not_exercised"}}
	if ctx == nil {
		return result, fmt.Errorf("login1 inspection context required")
	}
	if runtime.GOOS != "linux" {
		result.Snapshot = model.LinuxLogin1Snapshot{Status: "unsupported", Warnings: []string{"This diagnostic requires Linux; no bus access attempted."}}
		return result, fmt.Errorf("login1 inspection requires Linux")
	}
	versionCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	content, stderr, versionErr := runLogin1Command("/usr/bin/busctl")(versionCtx, []string{"--version"}, 8192)
	cancel()
	if versionErr == nil && len(content) == 0 {
		versionErr = fmt.Errorf("busctl version probe returned no output")
	}
	result.Tool.Stderr = stderr
	if len(content) > 0 {
		result.Tool.Content = content
		result.Tool.SHA256 = fmt.Sprintf("%x", sha256.Sum256(content))
	}
	if versionErr != nil {
		result.Tool.Status = "error"
		result.Tool.Error = versionErr.Error()
	} else {
		result.Tool.Status = "observed"
	}
	var sourceErr error
	result.Snapshot, sourceErr = collectPlatformLogin1(ctx)
	return result, errors.Join(versionErr, sourceErr)
}
