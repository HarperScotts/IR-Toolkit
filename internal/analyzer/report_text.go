package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ir-toolkit/internal/model"
)

func WriteCaseReportText(
	path string,
	report model.CaseReport,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return err
	}

	builder :=
		&strings.Builder{}

	fmt.Fprintln(
		builder,
		"IR Toolkit Case Report",
	)

	fmt.Fprintln(
		builder,
		"======================",
	)

	fmt.Fprintln(builder)

	fmt.Fprintf(
		builder,
		"Host                 : %s\n",
		report.Host.Hostname,
	)

	fmt.Fprintf(
		builder,
		"Collection Mode      : %s\n",
		report.Coverage.CollectionMode,
	)

	fmt.Fprintf(
		builder,
		"Historical Coverage  : %d%%\n",
		report.Coverage.HistoricalCoverage,
	)

	fmt.Fprintf(
		builder,
		"Snapshot Coverage    : %d%%\n",
		report.Coverage.SnapshotCoverage,
	)

	fmt.Fprintln(builder)

	fmt.Fprintln(
		builder,
		"Executive Summary",
	)

	fmt.Fprintln(
		builder,
		"-----------------",
	)

	fmt.Fprintf(
		builder,
		"Overall Severity     : %s\n",
		report.Summary.OverallSeverity,
	)

	fmt.Fprintf(
		builder,
		"Risk Score           : %d\n",
		report.Summary.RiskScore,
	)

	fmt.Fprintf(
		builder,
		"Top Findings         : %d\n",
		report.Summary.TopFindingCount,
	)

	fmt.Fprintf(
		builder,
		"Historical Chains    : %d\n",
		report.Summary.HistoricalChainCount,
	)

	fmt.Fprintf(
		builder,
		"Summary              : %s\n",
		report.Summary.Statement,
	)

	fmt.Fprintln(builder)

	writeReportFindings(
		builder,
		report,
	)

	writeReportChains(
		builder,
		report,
	)

	writeReportTimeline(
		builder,
		report,
	)

	writeReportEvidenceGaps(
		builder,
		report,
	)

	return os.WriteFile(
		path,
		[]byte(
			builder.String(),
		),
		0644,
	)
}

func writeReportFindings(
	builder *strings.Builder,
	report model.CaseReport,
) {

	fmt.Fprintln(
		builder,
		"Top Findings",
	)

	fmt.Fprintln(
		builder,
		"------------",
	)

	if len(report.TopFindings) == 0 {

		fmt.Fprintln(
			builder,
			"No high-interest findings were produced.",
		)

		fmt.Fprintln(builder)

		return
	}

	for index, finding := range report.TopFindings {

		fmt.Fprintf(
			builder,
			"%d. [%s] %s\n",
			index+1,
			strings.ToUpper(
				finding.Severity,
			),
			finding.Title,
		)

		fmt.Fprintf(
			builder,
			"   Source : %s\n",
			finding.Source,
		)

		fmt.Fprintf(
			builder,
			"   Score  : %d\n",
			finding.Score,
		)

		if finding.Object != "" {

			fmt.Fprintf(
				builder,
				"   Object : %s\n",
				finding.Object,
			)
		}

		if finding.User != "" {

			fmt.Fprintf(
				builder,
				"   User   : %s\n",
				finding.User,
			)
		}

		for _, reason := range finding.Reasons {

			fmt.Fprintf(
				builder,
				"   - %s\n",
				reason,
			)
		}

		fmt.Fprintln(builder)
	}
}

func writeReportChains(
	builder *strings.Builder,
	report model.CaseReport,
) {

	fmt.Fprintln(
		builder,
		"Historical Chains",
	)

	fmt.Fprintln(
		builder,
		"-----------------",
	)

	if len(
		report.HistoricalChains,
	) == 0 {

		fmt.Fprintln(
			builder,
			"No correlated historical chains were produced.",
		)

		fmt.Fprintln(builder)

		return
	}

	for index, chain := range report.HistoricalChains {

		fmt.Fprintf(
			builder,
			"%d. [%s / %s confidence]\n",
			index+1,
			strings.ToUpper(
				chain.Severity,
			),
			chain.Confidence,
		)

		fmt.Fprintf(
			builder,
			"   Score   : %d\n",
			chain.Score,
		)

		fmt.Fprintf(
			builder,
			"   Summary : %s\n",
			chain.Summary,
		)

		for _, reason := range chain.Reasons {

			fmt.Fprintf(
				builder,
				"   - %s\n",
				reason,
			)
		}

		fmt.Fprintln(builder)
	}
}

func writeReportTimeline(
	builder *strings.Builder,
	report model.CaseReport,
) {

	fmt.Fprintln(
		builder,
		"Timeline Highlights",
	)

	fmt.Fprintln(
		builder,
		"-------------------",
	)

	for _, event := range report.TimelineHighlights {

		timeValue :=
			"-"

		if !event.Timestamp.IsZero() {

			timeValue =
				event.Timestamp.
					Format(
						"2006-01-02 15:04:05Z07:00",
					)
		}

		fmt.Fprintf(
			builder,
			"%s  %-18s %-28s %s\n",
			timeValue,
			event.Category,
			event.Type,
			event.Description,
		)
	}

	fmt.Fprintln(builder)
}

func writeReportEvidenceGaps(
	builder *strings.Builder,
	report model.CaseReport,
) {

	fmt.Fprintln(
		builder,
		"Known Evidence Gaps",
	)

	fmt.Fprintln(
		builder,
		"-------------------",
	)

	if len(report.EvidenceGaps) == 0 {

		fmt.Fprintln(
			builder,
			"No known evidence coverage gaps were recorded.",
		)

		return
	}

	for _, gap := range report.EvidenceGaps {

		fmt.Fprintf(
			builder,
			"- %s\n",
			gap,
		)
	}
}
