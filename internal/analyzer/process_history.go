package analyzer

import (
	"context"
	"sort"

	"ir-toolkit/internal/model"
)

func AnalyzeProcessHistory(
	ctx context.Context,
	events model.ProcessEventSnapshot,
	login model.LoginAnalysis,
	currentProcesses []model.Process,
) model.ProcessHistoryAnalysis {

	result :=
		model.ProcessHistoryAnalysis{
			Processes: make(
				[]model.HistoricalProcess,
				0,
			),

			Edges: make(
				[]model.HistoricalProcessEdge,
				0,
			),

			Findings: make(
				[]model.HistoricalProcessFinding,
				0,
			),
		}

	loginMap :=
		buildHistoricalLoginMap(
			login,
		)

	currentProcessMap :=
		buildCurrentProcessMap(
			currentProcesses,
		)

	for _, event := range events.Events {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		if event.EventID != 4688 {
			continue
		}

		process :=
			buildHistoricalProcess(
				event,
				loginMap,
				currentProcessMap,
			)

		result.Processes =
			append(
				result.Processes,
				process,
			)
	}

	result.Edges =
		buildHistoricalProcessEdges(
			result.Processes,
		)

	result.Findings =
		analyzeHistoricalProcesses(
			result.Processes,
			result.Edges,
		)

	result.Statistics.EventCount =
		uint32(
			len(events.Events),
		)

	result.Statistics.HistoricalProcessCount =
		uint32(
			len(result.Processes),
		)

	result.Statistics.ParentChildEdgeCount =
		uint32(
			len(result.Edges),
		)

	for _, process := range result.Processes {

		if process.MatchedLogin {
			result.Statistics.
				MatchedLoginCount++
		}

		if process.CurrentProcess {
			result.Statistics.
				MatchedCurrentProcessCount++
		}
	}

	result.Statistics.FindingCount =
		uint32(
			len(result.Findings),
		)

	for _, finding := range result.Findings {

		switch finding.Severity {

		case "critical":
			result.Statistics.
				CriticalCount++

		case "high":
			result.Statistics.
				HighCount++

		case "medium":
			result.Statistics.
				MediumCount++
		}
	}

	sort.Slice(
		result.Processes,
		func(i, j int) bool {

			return result.Processes[i].
				Timestamp.
				Before(
					result.Processes[j].
						Timestamp,
				)
		},
	)

	return result
}
