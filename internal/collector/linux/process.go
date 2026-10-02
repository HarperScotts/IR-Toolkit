package linux

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ir-toolkit/internal/model"
)

type ProcessCollector struct{}

func (c *ProcessCollector) Name() string {
	return "linux_process"
}

func (c *ProcessCollector) Collect(ctx context.Context) (any, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	processes := make([]model.Process, 0, len(entries))

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return processes, ctx.Err()
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}

		process, err := readProcess(uint32(pid))
		if err != nil {
			// 进程可能在采集过程中退出，这是正常情况。
			continue
		}

		processes = append(processes, process)
	}

	return processes, nil
}

func readProcess(pid uint32) (model.Process, error) {
	pidString := strconv.FormatUint(uint64(pid), 10)

	base := filepath.Join(
		"/proc",
		pidString,
	)

	// /proc/<pid>/stat
	statData, err := os.ReadFile(
		filepath.Join(base, "stat"),
	)
	if err != nil {
		return model.Process{}, err
	}

	name, ppid, err := parseStat(string(statData))
	if err != nil {
		return model.Process{}, err
	}

	// /proc/<pid>/cmdline
	commandLine := ""

	if data, err := os.ReadFile(
		filepath.Join(base, "cmdline"),
	); err == nil {
		commandLine = strings.TrimSpace(
			strings.ReplaceAll(
				string(data),
				"\x00",
				" ",
			),
		)
	}

	// /proc/<pid>/exe
	path := ""

	if target, err := os.Readlink(
		filepath.Join(base, "exe"),
	); err == nil {
		path = target
	}

	// /proc/<pid>/status
	user := ""

	if data, err := os.ReadFile(
		filepath.Join(base, "status"),
	); err == nil {
		user = uidFromStatus(string(data))
	}

	return model.Process{
		PID:         pid,
		PPID:        ppid,
		Name:        name,
		Path:        path,
		CommandLine: commandLine,
		User:        user,
	}, nil
}

// parseStat parses:
//
// /proc/<pid>/stat
//
// The format begins with:
//
// pid (comm) state ppid ...
//
// The tricky part is that comm may itself contain ')'.
// Therefore we use the LAST ')' instead of the first ')'.
func parseStat(s string) (string, uint32, error) {
	openParen := strings.IndexByte(s, '(')
	closeParen := strings.LastIndexByte(s, ')')

	if openParen < 0 || closeParen < 0 || closeParen <= openParen {
		return "", 0, fmt.Errorf("invalid /proc stat format")
	}

	name := s[openParen+1 : closeParen]

	rest := strings.Fields(
		s[closeParen+1:],
	)

	// rest[0] = state
	// rest[1] = ppid
	if len(rest) < 2 {
		return "", 0, fmt.Errorf("invalid /proc stat fields")
	}

	ppid, err := strconv.ParseUint(
		rest[1],
		10,
		32,
	)
	if err != nil {
		return "", 0, fmt.Errorf(
			"invalid ppid %q: %w",
			rest[1],
			err,
		)
	}

	return name, uint32(ppid), nil
}

func uidFromStatus(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "Uid:") {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) >= 2 {
			return fields[1]
		}
	}

	return ""
}
