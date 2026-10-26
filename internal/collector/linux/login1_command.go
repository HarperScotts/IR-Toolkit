package linux

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

var errLogin1OutputLimit = errors.New("login1 command output limit exceeded; stdout discarded, stderr may be truncated")

type login1Capture struct {
	content  []byte
	maximum  int
	overflow bool
}

func (b *login1Capture) Write(p []byte) (int, error) {
	remaining := b.maximum - len(b.content)
	if len(p) > remaining {
		b.overflow = true
	}
	b.content = append(b.content, p[:min(remaining, len(p))]...)
	return len(p), nil // Drain without unbounded allocation; context bounds execution.
}

func runLogin1Command(executable string) login1Run {
	return func(ctx context.Context, args []string, limit int) ([]byte, []byte, error) {
		out, diagnostic := &login1Capture{maximum: limit}, &login1Capture{maximum: 8192}
		command := exec.CommandContext(ctx, executable, args...)
		command.Env = []string{"LC_ALL=C", "LANG=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
		command.Stdout, command.Stderr = out, diagnostic
		command.WaitDelay = 100 * time.Millisecond
		err := errors.Join(command.Run(), ctx.Err())
		if out.overflow || diagnostic.overflow {
			return nil, diagnostic.content, errors.Join(err, errLogin1OutputLimit)
		}
		return out.content, diagnostic.content, err
	}
}
