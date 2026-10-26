package analyzer

import "ir-toolkit/internal/model"

func buildHistoricalParentChildCorrelationEdges(
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	history model.ProcessHistoryAnalysis,
) {
	// History may be provided independently of the current Analyzer run. Do
	// not promote stale or inconsistent edges without validating their endpoints.
	approved := make(map[model.HistoricalProcessEdge]struct{})
	for _, edge := range buildHistoricalProcessEdges(history.Processes) {
		approved[edge] = struct{}{}
	}

	for _, edge := range history.Edges {
		if _, ok := approved[edge]; !ok {
			continue
		}

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

						Description: "4688 CreatorProcessId resolves to a unique, strictly earlier historical instance already matched to the current snapshot",
					},
					{
						Type:        "creator_path",
						Description: "4688 creator path agrees with the historical and matched current process paths; ambiguous or unknown lifetimes are not linked",
					},
				},
			},
		)
	}
}
