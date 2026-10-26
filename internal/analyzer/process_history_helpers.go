package analyzer

import (
	"fmt"
	"ir-toolkit/internal/model"
	"path/filepath"
	"strings"
	"time"
)

func historicalProcessID(
	pid uint32,
	timestamp time.Time,
) string {

	return fmt.Sprintf(
		"historical-process:%d:%d",
		pid,
		timestamp.UnixNano(),
	)
}

func historicalProcessName(
	path string,
) string {

	value :=
		strings.TrimSpace(
			path,
		)

	if value == "" {
		return ""
	}

	value =
		strings.ReplaceAll(
			value,
			`\`,
			"/",
		)

	return filepath.Base(
		value,
	)
}

func buildHistoricalLoginMap(
	login model.LoginAnalysis,
) map[string]model.LoginSessionAnalysis {

	result :=
		make(
			map[string]model.LoginSessionAnalysis,
		)

	for _, session := range login.Sessions {

		logonID :=
			normalizeLogonID(
				session.LogonID,
			)

		if logonID == "" {
			continue
		}

		result[logonID] =
			session
	}

	return result
}

func buildCurrentProcessMap(
	processes []model.Process,
) map[uint32]model.Process {

	result :=
		make(
			map[uint32]model.Process,
		)

	for _, process := range processes {
		if process.PID == 0 {
			continue
		}

		if _, exists := result[process.PID]; exists {
			// Keep a zero sentinel so a third occurrence cannot restore a match.
			// Duplicate PIDs in a current snapshot are ambiguous, even if equal.
			result[process.PID] = model.Process{}
			continue
		}
		result[process.PID] = process
	}

	return result
}

func buildHistoricalProcess(
	event model.ProcessEvent,
	loginMap map[string]model.LoginSessionAnalysis,
	currentProcessMap map[uint32]model.Process,
) model.HistoricalProcess {

	logonID :=
		normalizeLogonID(
			event.SubjectLogonID,
		)

	process :=
		model.HistoricalProcess{
			ID: historicalProcessID(
				event.NewProcessID,
				event.Timestamp,
			),

			Timestamp: event.Timestamp,

			PID: event.NewProcessID,

			ParentPID: event.ProcessID,

			ProcessPath: event.NewProcessName,

			ProcessName: historicalProcessName(
				event.NewProcessName,
			),

			ParentProcessName: event.ParentProcessName,

			CommandLine: event.CommandLine,

			User: event.SubjectUserName,

			Domain: event.SubjectDomainName,

			LogonID: logonID,

			TokenElevationType: event.TokenElevationType,

			MandatoryLabel: event.MandatoryLabel,
		}

	if _, exists :=
		loginMap[logonID]; exists {

		process.MatchedLogin = true
	}

	if current, exists :=
		currentProcessMap[event.NewProcessID]; exists {

		// PID and executable path can both recur after a process exits.
		// With today's schema, only exact known time agreement is accepted;
		// audit timestamps may differ from creation time, so do not use a
		// guessed tolerance or fall back to a path-only match.
		path := normalizeArtifactPath(event.NewProcessName)
		if event.NewProcessID != 0 && current.PID == event.NewProcessID &&
			!current.StartTime.IsZero() && !event.Timestamp.IsZero() &&
			current.StartTime.Equal(event.Timestamp) && path != "" &&
			normalizeArtifactPath(current.Path) == path {

			process.CurrentProcess =
				true

			process.CurrentProcessPath =
				current.Path
		}
	}

	return process
}
