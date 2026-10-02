//go:build windows

package windows

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/model"
)

type ProcessCollector struct{}

func (c *ProcessCollector) Name() string {
	return "windows_process"
}

func (c *ProcessCollector) Collect(
	ctx context.Context,
) (any, error) {

	snapshot, err := windows.CreateToolhelp32Snapshot(
		windows.TH32CS_SNAPPROCESS,
		0,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"CreateToolhelp32Snapshot: %w",
			err,
		)
	}

	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32

	entry.Size = uint32(
		unsafe.Sizeof(entry),
	)

	if err := windows.Process32First(
		snapshot,
		&entry,
	); err != nil {
		return nil, fmt.Errorf(
			"Process32First: %w",
			err,
		)
	}

	processes := make(
		[]model.Process,
		0,
		256,
	)

	for {
		select {
		case <-ctx.Done():
			return processes, ctx.Err()

		default:
		}

		process := collectProcess(entry)

		processes = append(
			processes,
			process,
		)

		if err := windows.Process32Next(
			snapshot,
			&entry,
		); err != nil {

			if err == windows.ERROR_NO_MORE_FILES {
				break
			}

			return processes, fmt.Errorf(
				"Process32Next: %w",
				err,
			)
		}
	}

	return processes, nil
}

func collectProcess(
	entry windows.ProcessEntry32,
) model.Process {

	process := model.Process{
		PID:  entry.ProcessID,
		PPID: entry.ParentProcessID,

		Name: windows.UTF16ToString(
			entry.ExeFile[:],
		),
	}

	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		entry.ProcessID,
	)

	if err != nil {
		return process
	}

	defer windows.CloseHandle(handle)

	// -------------------------------------------------
	// Image Path
	// -------------------------------------------------

	process.Path = getProcessPath(handle)

	// -------------------------------------------------
	// Session ID
	// -------------------------------------------------

	process.SessionID = getProcessSessionID(
		entry.ProcessID,
	)

	// -------------------------------------------------
	// Start Time
	// -------------------------------------------------

	process.StartTime = getProcessStartTime(
		handle,
	)

	// -------------------------------------------------
	// CommandLine
	// -------------------------------------------------

	process.CommandLine = getProcessCommandLine(
		handle,
	)

	// -------------------------------------------------
	// User / Integrity
	// -------------------------------------------------

	user, integrity, rid, authenticationID := getProcessSecurityInfo(handle)

	process.User = user
	process.IntegrityLevel = integrity
	process.IntegrityRID = rid
	process.AuthenticationID = authenticationID

	return process
}

func getProcessPath(
	process windows.Handle,
) string {

	buffer := make(
		[]uint16,
		32768,
	)

	size := uint32(len(buffer))

	err := windows.QueryFullProcessImageName(
		process,
		0,
		&buffer[0],
		&size,
	)

	if err != nil {
		return ""
	}

	return windows.UTF16ToString(
		buffer[:size],
	)
}

func getProcessSessionID(
	pid uint32,
) uint32 {

	var sessionID uint32

	if err := windows.ProcessIdToSessionId(
		pid,
		&sessionID,
	); err != nil {
		return 0
	}

	return sessionID
}

func getProcessStartTime(
	process windows.Handle,
) time.Time {

	var creation windows.Filetime
	var exit windows.Filetime
	var kernel windows.Filetime
	var user windows.Filetime

	if err := windows.GetProcessTimes(
		process,
		&creation,
		&exit,
		&kernel,
		&user,
	); err != nil {
		return time.Time{}
	}

	// Windows FILETIME:
	// 100-nanosecond intervals since 1601-01-01 UTC.
	const windowsToUnixEpoch = uint64(
		116444736000000000,
	)

	ticks := uint64(creation.HighDateTime)<<32 |
		uint64(creation.LowDateTime)

	if ticks < windowsToUnixEpoch {
		return time.Time{}
	}

	unix100ns := ticks - windowsToUnixEpoch

	seconds := int64(unix100ns / 10000000)

	nanoseconds := int64(
		(unix100ns % 10000000) * 100,
	)

	return time.Unix(
		seconds,
		nanoseconds,
	).UTC()
}
