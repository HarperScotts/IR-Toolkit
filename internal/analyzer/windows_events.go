package analyzer

import (
	"context"
	"sort"

	"ir-toolkit/internal/model"
)

func AnalyzeWindowsEvents(
	ctx context.Context,
	snapshot model.WindowsEventSnapshot,
) model.WindowsEventAnalysis {

	result :=
		model.WindowsEventAnalysis{
			Activities: make(
				[]model.WindowsActivity,
				0,
			),

			Findings: make(
				[]model.WindowsEventFinding,
				0,
			),
		}

	result.Statistics.RawEventCount =
		uint32(
			len(snapshot.Events),
		)

	for _, event := range snapshot.Events {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		switch event.DefinitionID {

		case "task_scheduler":

			activities,
				findings :=
				analyzeTaskSchedulerEvent(
					event,
				)

			result.Activities =
				append(
					result.Activities,
					activities...,
				)

			result.Findings =
				append(
					result.Findings,
					findings...,
				)

		case "wmi_activity":

			activities,
				findings :=
				analyzeWMIEvent(
					event,
				)

			result.Activities =
				append(
					result.Activities,
					activities...,
				)

			result.Findings =
				append(
					result.Findings,
					findings...,
				)

		case "terminal_services":

			activities,
				findings :=
				analyzeTerminalServicesEvent(
					event,
				)

			result.Activities =
				append(
					result.Activities,
					activities...,
				)

			result.Findings =
				append(
					result.Findings,
					findings...,
				)
		}
	}

	sort.SliceStable(
		result.Activities,
		func(i, j int) bool {

			return result.Activities[i].
				Timestamp.
				Before(
					result.Activities[j].
						Timestamp,
				)
		},
	)

	buildWindowsEventAnalysisStatistics(
		&result,
	)

	return result
}

func buildWindowsEventAnalysisStatistics(
	result *model.WindowsEventAnalysis,
) {

	result.Statistics.ActivityCount =
		uint32(
			len(result.Activities),
		)

	result.Statistics.FindingCount =
		uint32(
			len(result.Findings),
		)

	for _, activity := range result.Activities {

		switch activity.Category {

		case "scheduled_task":

			result.Statistics.
				TaskActivityCount++

		case "wmi":

			result.Statistics.
				WMIActivityCount++

		case "remote_session":

			result.Statistics.
				TerminalServicesActivityCount++
		}
	}

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

		case "low":

			result.Statistics.
				LowCount++
		}
	}
}
