package analyzer

import (
	"context"
	"sort"

	"ir-toolkit/internal/model"
)

func AnalyzeHistoricalCorrelation(
	ctx context.Context,
	login model.LoginAnalysis,
	processHistory model.ProcessHistoryAnalysis,
	powerShell model.PowerShellAnalysis,
	windowsEvents model.WindowsEventAnalysis,
) model.HistoricalCorrelationAnalysis {

	result :=
		model.HistoricalCorrelationAnalysis{
			Nodes: make(
				[]model.HistoricalChainNode,
				0,
			),

			Edges: make(
				[]model.CorrelationEdge,
				0,
			),

			Chains: make(
				[]model.HistoricalChain,
				0,
			),
		}

	nodeSeen :=
		make(
			map[string]struct{},
		)

	edgeSeen :=
		make(
			map[string]struct{},
		)

	buildHistoricalCorrelationNodes(
		ctx,
		&result,
		nodeSeen,
		login,
		processHistory,
		powerShell,
		windowsEvents,
	)

	buildLoginProcessCorrelationEdges(
		ctx,
		&result,
		edgeSeen,
		login,
		processHistory,
	)

	buildHistoricalParentChildCorrelationEdges(
		&result,
		edgeSeen,
		processHistory,
	)

	buildProcessPowerShellCorrelationEdges(
		ctx,
		&result,
		edgeSeen,
		processHistory,
		powerShell,
	)

	buildRDPSessionCorrelationEdges(
		ctx,
		&result,
		edgeSeen,
		login,
		windowsEvents,
	)

	buildProcessGenericEventCorrelationEdges(
		ctx,
		&result,
		edgeSeen,
		processHistory,
		windowsEvents,
	)

	result.Chains =
		buildHistoricalCorrelationChains(
			result,
		)

	sort.SliceStable(
		result.Nodes,
		func(i, j int) bool {

			return result.Nodes[i].
				Timestamp.
				Before(
					result.Nodes[j].
						Timestamp,
				)
		},
	)

	buildHistoricalCorrelationStatistics(
		&result,
	)

	return result
}

func buildHistoricalCorrelationStatistics(
	result *model.HistoricalCorrelationAnalysis,
) {

	result.Statistics.NodeCount =
		uint32(
			len(result.Nodes),
		)

	result.Statistics.EdgeCount =
		uint32(
			len(result.Edges),
		)

	result.Statistics.ChainCount =
		uint32(
			len(result.Chains),
		)

	for _, edge := range result.Edges {

		switch edge.Confidence {

		case "high":

			result.Statistics.
				HighConfidenceEdgeCount++

		case "medium":

			result.Statistics.
				MediumConfidenceEdgeCount++

		case "low":

			result.Statistics.
				LowConfidenceEdgeCount++
		}
	}

	for _, chain := range result.Chains {

		switch chain.Severity {

		case "critical":

			result.Statistics.
				CriticalChainCount++

		case "high":

			result.Statistics.
				HighChainCount++

		case "medium":

			result.Statistics.
				MediumChainCount++
		}
	}
}
