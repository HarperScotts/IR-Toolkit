package analyzer

import "ir-toolkit/internal/model"

func buildHistoricalParentChildCorrelationEdges(
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	history model.ProcessHistoryAnalysis,
) {

	for _, edge := range history.Edges {

		addCorrelationEdge(
			result,
			seen,
			model.CorrelationEdge{
				From: edge.ParentID,

				To: edge.ChildID,

				Type: "parent_child",

				Confidence: "high",

				Score: 90,

				Basis: []model.CorrelationEvidence{
					{
						Type: "creator_pid",

						Description: "4688 CreatorProcessId resolves to the most recent matching historical process instance",
					},
				},
			},
		)
	}
}
