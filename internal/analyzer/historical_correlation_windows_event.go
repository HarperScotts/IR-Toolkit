package analyzer

import (
	"context"
	"fmt"
	"time"

	"ir-toolkit/internal/model"
)

const genericProcessCorrelationWindow = 30 * time.Minute

func buildProcessGenericEventCorrelationEdges(
	ctx context.Context,
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	history model.ProcessHistoryAnalysis,
	windowsEvents model.WindowsEventAnalysis,
) {

	byPID :=
		make(
			map[uint32][]model.HistoricalProcess,
		)

	for _, process := range history.Processes {

		byPID[process.PID] =
			append(
				byPID[process.PID],
				process,
			)
	}

	for _, activity := range windowsEvents.Activities {

		select {
		case <-ctx.Done():
			return
		default:
		}

		if activity.ProcessID == 0 {
			continue
		}

		switch activity.Category {

		case "scheduled_task",
			"wmi":

		default:
			continue
		}

		candidates :=
			byPID[activity.ProcessID]

		var best *model.HistoricalProcess

		for index := range candidates {

			candidate :=
				&candidates[index]

			if candidate.Timestamp.
				After(
					activity.Timestamp,
				) {

				continue
			}

			if !withinTimeWindow(
				candidate.Timestamp,
				activity.Timestamp,
				genericProcessCorrelationWindow,
			) {

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

		addCorrelationEdge(
			result,
			seen,
			model.CorrelationEdge{
				From: best.ID,

				To: activity.ID,

				Type: "process_windows_event",

				Confidence: "medium",

				Score: 70,

				Basis: []model.CorrelationEvidence{
					{
						Type: "pid",

						Value: fmt.Sprintf(
							"%d",
							activity.ProcessID,
						),

						Description: "event process ID matches a historical process",
					},
					{
						Type: "time",

						Description: "event occurred within the process correlation window",
					},
				},

				Timestamp: activity.Timestamp,
			},
		)
	}
}
