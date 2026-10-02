package analyzer

import (
	"fmt"

	"ir-toolkit/internal/model"
)

func buildExecutiveSummary(
	report *model.CaseReport,
) {

	score := 0

	var critical uint32
	var high uint32
	var medium uint32

	for _, finding := range report.TopFindings {

		switch finding.Severity {

		case "critical":

			critical++

			if finding.Score > score {
				score =
					finding.Score
			}

		case "high":

			high++

			if finding.Score > score {
				score =
					finding.Score
			}

		case "medium":

			medium++

			if finding.Score > score {
				score =
					finding.Score
			}
		}
	}

	for _, chain := range report.HistoricalChains {

		if chain.Score > score {
			score =
				chain.Score
		}

		switch chain.Severity {

		case "critical":
			critical++

		case "high":
			high++

		case "medium":
			medium++
		}
	}

	severity :=
		reportSeverity(
			score,
		)

	statement :=
		fmt.Sprintf(
			"%d top findings and %d correlated historical chains were identified.",
			len(report.TopFindings),
			len(report.HistoricalChains),
		)

	if len(report.EvidenceGaps) > 0 {

		statement +=
			fmt.Sprintf(
				" Evidence coverage has %d known gap(s).",
				len(
					report.EvidenceGaps,
				),
			)
	}

	report.Summary =
		model.ReportExecutiveSummary{
			OverallSeverity: severity,

			RiskScore: score,

			TopFindingCount: uint32(
				len(
					report.TopFindings,
				),
			),

			HistoricalChainCount: uint32(
				len(
					report.HistoricalChains,
				),
			),

			CriticalCount: critical,

			HighCount: high,

			MediumCount: medium,

			Statement: statement,
		}
}

func reportSeverity(
	score int,
) string {

	switch {

	case score >= 100:
		return "critical"

	case score >= 70:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}
