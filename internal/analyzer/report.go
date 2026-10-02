package analyzer

import (
	"sort"
	"time"

	"ir-toolkit/internal/model"
)

func BuildCaseReport(
	casePath string,
	host model.HostInfo,
	manifest model.Manifest,
	capabilities model.AuditCapabilitySnapshot,
	fileAnalysis model.FileAnalysis,
	persistence model.PersistenceAnalysis,
	powerShell model.PowerShellAnalysis,
	windowsEvents model.WindowsEventAnalysis,
	history model.ProcessHistoryAnalysis,
	correlation model.HistoricalCorrelationAnalysis,
	timeline model.Timeline,
	ioc *model.IOCScanResult,
) model.CaseReport {

	report :=
		model.CaseReport{
			GeneratedAt: time.Now().UTC(),

			CasePath: casePath,

			Host: model.ReportHostSummary{
				Hostname: host.Hostname,
			},

			Collection: model.ReportCollectionSummary{
				Since: manifest.CollectionSince,

				Until: manifest.CollectionUntil,
			},

			Coverage: model.ReportCoverageSummary{
				CollectionMode: capabilities.CollectionMode,

				HistoricalCoverage: capabilities.HistoricalCoverage,

				SnapshotCoverage: capabilities.SnapshotCoverage,
			},

			TopFindings: make(
				[]model.ReportFinding,
				0,
			),

			HistoricalChains: make(
				[]model.ReportChainSummary,
				0,
			),

			TimelineHighlights: make(
				[]model.ReportTimelineEvent,
				0,
			),

			EvidenceGaps: make(
				[]string,
				0,
			),
		}

	appendFileReportFindings(
		&report,
		fileAnalysis,
	)

	appendPersistenceReportFindings(
		&report,
		persistence,
	)

	appendPowerShellReportFindings(
		&report,
		powerShell,
	)

	appendWindowsEventReportFindings(
		&report,
		windowsEvents,
	)

	appendHistoricalProcessReportFindings(
		&report,
		history,
	)

	if ioc != nil {

		appendIOCReportFindings(
			&report,
			*ioc,
		)
	}

	appendHistoricalChains(
		&report,
		correlation,
	)

	appendTimelineHighlights(
		&report,
		timeline,
	)

	appendEvidenceGaps(
		&report,
		capabilities,
	)

	sort.SliceStable(
		report.TopFindings,
		func(i, j int) bool {

			if report.TopFindings[i].Score ==
				report.TopFindings[j].Score {

				return report.TopFindings[i].
					Severity >
					report.TopFindings[j].
						Severity
			}

			return report.TopFindings[i].
				Score >
				report.TopFindings[j].
					Score
		},
	)

	if len(report.TopFindings) > 25 {

		report.TopFindings =
			report.TopFindings[:25]
	}

	buildExecutiveSummary(
		&report,
	)

	return report
}
