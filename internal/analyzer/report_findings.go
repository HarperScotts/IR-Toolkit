package analyzer

import (
	"fmt"
	"ir-toolkit/internal/model"
)

func appendFileReportFindings(
	report *model.CaseReport,
	analysis model.FileAnalysis,
) {

	for _, finding := range analysis.Findings {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "file",

					ID: finding.ID,

					Severity: finding.Severity,

					Score: finding.Score,

					Title: finding.Title,

					Object: finding.Path,

					Reasons: finding.Reasons,
				},
			)
	}
}

func appendPersistenceReportFindings(
	report *model.CaseReport,
	analysis model.PersistenceAnalysis,
) {

	for _, finding := range analysis.Findings {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "persistence",

					ID: finding.ID,

					Severity: finding.Severity,

					Score: finding.Score,

					Title: finding.Title,

					Object: finding.Name,

					User: finding.User,

					Reasons: finding.Reasons,
				},
			)
	}
}

func appendPowerShellReportFindings(
	report *model.CaseReport,
	analysis model.PowerShellAnalysis,
) {

	for _, finding := range analysis.Findings {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "powershell",

					ID: finding.ID,

					Severity: finding.Severity,

					Score: finding.Score,

					Title: finding.Title,

					Timestamp: finding.Timestamp,

					Object: finding.ProcessName,

					User: finding.User,

					Reasons: finding.Reasons,
				},
			)
	}
}

func appendWindowsEventReportFindings(
	report *model.CaseReport,
	analysis model.WindowsEventAnalysis,
) {

	for _, finding := range analysis.Findings {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "windows_event",

					ID: finding.ID,

					Severity: finding.Severity,

					Score: finding.Score,

					Title: finding.Title,

					Timestamp: finding.Timestamp,

					Object: finding.Object,

					User: finding.User,

					Reasons: finding.Reasons,
				},
			)
	}
}

func appendHistoricalProcessReportFindings(
	report *model.CaseReport,
	analysis model.ProcessHistoryAnalysis,
) {

	for _, finding := range analysis.Findings {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "process_history",

					ID: finding.ID,

					Severity: finding.Severity,

					Score: finding.Score,

					Title: finding.Title,

					Timestamp: finding.Timestamp,

					Object: finding.ProcessName,

					User: finding.User,

					Reasons: finding.Reasons,
				},
			)
	}
}

func appendIOCReportFindings(
	report *model.CaseReport,
	result model.IOCScanResult,
) {

	for index, match := range result.Matches {

		report.TopFindings =
			append(
				report.TopFindings,

				model.ReportFinding{
					Source: "ioc",

					ID: fmt.Sprintf(
						"IOC-%d",
						index+1,
					),

					Severity: "medium",

					Score: 50,

					Title: "IOC match: " +
						match.IOCType,

					Object: match.Object,

					Reasons: []string{
						"evidence matched supplied IOC value: " +
							match.IOCValue,
					},
				},
			)
	}
}
