package analyzer

import (
	"context"

	"ir-toolkit/internal/model"
)

func AnalyzePowerShell(
	ctx context.Context,
	events model.PowerShellEventSnapshot,
	history model.ProcessHistoryAnalysis,
) model.PowerShellAnalysis {

	result :=
		model.PowerShellAnalysis{
			ScriptBlocks: make(
				[]model.PowerShellScriptBlock,
				0,
			),

			Findings: make(
				[]model.PowerShellFinding,
				0,
			),
		}

	result.Statistics.RawEventCount =
		uint32(
			len(events.Events),
		)

	for _, event := range events.Events {

		switch event.EventID {

		case 4103:

			result.Statistics.
				ModuleEventCount++

		case 4104:

			result.Statistics.
				ScriptBlockEventCount++
		}
	}

	result.ScriptBlocks =
		rebuildPowerShellScriptBlocks(
			events.Events,
		)

	correlatePowerShellBlocks(
		result.ScriptBlocks,
		history,
	)

	result.Statistics.ScriptBlockCount =
		uint32(
			len(result.ScriptBlocks),
		)

	for _, block := range result.ScriptBlocks {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		if block.Complete {

			result.Statistics.
				CompleteScriptBlockCount++

		} else {

			result.Statistics.
				IncompleteScriptBlockCount++
		}

		if block.
			RelatedHistoricalProcessID != "" {

			result.Statistics.
				MatchedHistoricalProcessCount++
		}

		finding :=
			analyzePowerShellBlock(
				block,
			)

		if finding != nil {

			result.Findings =
				append(
					result.Findings,
					*finding,
				)
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

		case "low":

			result.Statistics.
				LowCount++
		}
	}

	return result
}
