package analyzer

import "ir-toolkit/internal/model"

func appendHistoricalChains(
	report *model.CaseReport,
	analysis model.HistoricalCorrelationAnalysis,
) {

	for _, chain := range analysis.Chains {

		report.HistoricalChains =
			append(
				report.HistoricalChains,

				model.ReportChainSummary{
					ID: chain.ID,

					Severity: chain.Severity,

					Confidence: chain.Confidence,

					Score: chain.Score,

					StartTime: chain.StartTime,

					EndTime: chain.EndTime,

					Summary: chain.Summary,

					Reasons: chain.Reasons,
				},
			)
	}

	if len(report.HistoricalChains) > 10 {

		report.HistoricalChains =
			report.HistoricalChains[:10]
	}
}
