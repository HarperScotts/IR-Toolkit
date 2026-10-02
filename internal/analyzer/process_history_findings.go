package analyzer

import (
	"strings"

	"ir-toolkit/internal/model"
)

func analyzeHistoricalProcesses(
	processes []model.HistoricalProcess,
	edges []model.HistoricalProcessEdge,
) []model.HistoricalProcessFinding {

	result :=
		make(
			[]model.HistoricalProcessFinding,
			0,
		)

	processMap :=
		make(
			map[string]model.HistoricalProcess,
		)

	children :=
		make(
			map[string][]model.HistoricalProcess,
		)

	for _, process := range processes {

		processMap[process.ID] =
			process
	}

	for _, edge := range edges {

		child, exists :=
			processMap[edge.ChildID]

		if !exists {
			continue
		}

		children[edge.ParentID] =
			append(
				children[edge.ParentID],
				child,
			)
	}

	for _, process := range processes {

		score := 0

		reasons :=
			make(
				[]string,
				0,
			)

		name :=
			strings.ToLower(
				process.ProcessName,
			)

		if isShellProcessName(
			name,
		) {

			score += 10
		}

		if isHistoricalLOLBin(
			name,
		) {

			score += 20

			reasons =
				append(
					reasons,
					"historical process is a commonly abused Windows utility",
				)
		}

		if containsSuspiciousHistoricalArguments(
			process.CommandLine,
		) {

			score += 35

			reasons =
				append(
					reasons,
					"historical command line contains high-interest execution arguments",
				)
		}

		childList :=
			children[process.ID]

		if isShellProcessName(
			name,
		) {

			for _, child := range childList {

				if isHistoricalLOLBin(
					strings.ToLower(
						child.ProcessName,
					),
				) {

					score += 25

					reasons =
						append(
							reasons,
							"shell spawned a high-interest utility",
						)

					break
				}
			}
		}

		if process.MatchedLogin &&
			isShellProcessName(
				name,
			) {

			score += 15

			reasons =
				append(
					reasons,
					"shell belongs to a known login session",
				)
		}

		if score < 30 {
			continue
		}

		finding :=
			model.HistoricalProcessFinding{
				ID: "HISTPROC-" +
					sanitizeFindingID(
						process.ID,
					),

				Type: "historical_process",

				Title: "High-interest historical process execution",

				Timestamp: process.Timestamp,

				PID: process.PID,

				ProcessName: process.ProcessName,

				CommandLine: process.CommandLine,

				User: process.User,

				LogonID: process.LogonID,

				Score: score,

				Reasons: uniqueStrings(
					reasons,
				),

				RelatedProcessIDs: []string{
					process.ID,
				},
			}

		finding.Severity =
			historicalProcessSeverity(
				score,
			)

		result =
			append(
				result,
				finding,
			)
	}

	return result
}

func isHistoricalLOLBin(
	name string,
) bool {

	switch strings.ToLower(
		name,
	) {

	case "powershell.exe",
		"pwsh.exe",
		"certutil.exe",
		"bitsadmin.exe",
		"mshta.exe",
		"rundll32.exe",
		"regsvr32.exe",
		"wscript.exe",
		"cscript.exe",
		"wmic.exe",
		"curl.exe":

		return true
	}

	return false
}

func containsSuspiciousHistoricalArguments(
	command string,
) bool {

	value :=
		strings.ToLower(
			command,
		)

	patterns :=
		[]string{
			"-encodedcommand",
			"-enc ",
			"frombase64string",
			"downloadstring",
			"invoke-webrequest",
			"invoke-expression",
			"iex ",
			"javascript:",
			"regsvr32 /s",
			"scrobj.dll",
			"urlcache",
		}

	for _, pattern := range patterns {

		if strings.Contains(
			value,
			pattern,
		) {

			return true
		}
	}

	return false
}

func historicalProcessSeverity(
	score int,
) string {

	switch {

	case score >= 90:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}
