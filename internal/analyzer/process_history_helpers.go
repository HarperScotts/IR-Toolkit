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

		result[process.PID] =
			process
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

		/*
			PID 会复用，所以不能仅凭 PID 就认为一定
			是同一个进程。

			这里增加路径校验。
		*/

		if normalizeArtifactPath(
			current.Path,
		) ==
			normalizeArtifactPath(
				event.NewProcessName,
			) {

			process.CurrentProcess =
				true

			process.CurrentProcessPath =
				current.Path
		}
	}

	return process
}
