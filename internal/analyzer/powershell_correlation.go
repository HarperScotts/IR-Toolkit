package analyzer

import (
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

const powerShellProcessMatchWindow = 12 * time.Hour

func correlatePowerShellBlocks(
	blocks []model.PowerShellScriptBlock,
	history model.ProcessHistoryAnalysis,
) {

	processesByPID :=
		make(
			map[uint32][]model.HistoricalProcess,
		)

	for _, process := range history.Processes {

		name :=
			strings.ToLower(
				process.ProcessName,
			)

		if name != "powershell.exe" &&
			name != "pwsh.exe" {

			continue
		}

		processesByPID[process.PID] =
			append(
				processesByPID[process.PID],
				process,
			)
	}

	for index := range blocks {

		block :=
			&blocks[index]

		if block.ProcessID == 0 {
			continue
		}

		candidates :=
			processesByPID[block.ProcessID]

		var best *model.HistoricalProcess

		for candidateIndex := range candidates {

			candidate :=
				&candidates[candidateIndex]

			if candidate.Timestamp.
				After(
					block.Timestamp,
				) {

				continue
			}

			delta :=
				block.Timestamp.Sub(
					candidate.Timestamp,
				)

			if delta >
				powerShellProcessMatchWindow {

				continue
			}

			if best == nil ||
				candidate.Timestamp.
					After(
						best.Timestamp,
					) {

				best =
					candidate
			}
		}

		if best == nil {
			continue
		}

		block.
			RelatedHistoricalProcessID =
			best.ID

		block.
			RelatedProcessName =
			best.ProcessName

		block.
			RelatedCommandLine =
			best.CommandLine

		block.User =
			best.User

		block.LogonID =
			best.LogonID
	}
}
