package analyzer

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

func buildProcessPowerShellCorrelationEdges(
	ctx context.Context,
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	history model.ProcessHistoryAnalysis,
	powerShell model.PowerShellAnalysis,
) {

	processIDs :=
		make(
			map[string]struct{},
		)

	for _, process := range history.Processes {

		processIDs[process.ID] =
			struct{}{}
	}

	for _, block := range powerShell.ScriptBlocks {

		select {
		case <-ctx.Done():
			return
		default:
		}

		processID :=
			block.
				RelatedHistoricalProcessID

		if processID == "" {
			continue
		}

		if _, exists :=
			processIDs[processID]; !exists {

			continue
		}

		addCorrelationEdge(
			result,
			seen,
			model.CorrelationEdge{
				From: processID,

				To: block.ID,

				Type: "process_powershell",

				Confidence: "high",

				Score: 90,

				Basis: []model.CorrelationEvidence{
					{
						Type: "pid",

						Value: fmt.Sprintf(
							"%d",
							block.ProcessID,
						),

						Description: "4104 process ID matches a historical PowerShell process",
					},
					{
						Type: "time",

						Description: "4104 occurred after the matched PowerShell process creation",
					},
				},

				Timestamp: block.Timestamp,
			},
		)
	}
}
