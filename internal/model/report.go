package model

import "time"

type CaseReport struct {
	GeneratedAt time.Time `json:"generated_at"`

	CasePath string `json:"case_path"`

	Host ReportHostSummary `json:"host"`

	Collection ReportCollectionSummary `json:"collection"`

	Coverage ReportCoverageSummary `json:"coverage"`

	Summary ReportExecutiveSummary `json:"summary"`

	TopFindings []ReportFinding `json:"top_findings"`

	HistoricalChains []ReportChainSummary `json:"historical_chains"`

	TimelineHighlights []ReportTimelineEvent `json:"timeline_highlights"`

	EvidenceGaps []string `json:"evidence_gaps,omitempty"`
}

type ReportHostSummary struct {
	Hostname string `json:"hostname,omitempty"`

	OS string `json:"os,omitempty"`

	Architecture string `json:"architecture,omitempty"`
}

type ReportCollectionSummary struct {
	Since *time.Time `json:"since,omitempty"`

	Until *time.Time `json:"until,omitempty"`
}

type ReportCoverageSummary struct {
	CollectionMode string `json:"collection_mode,omitempty"`

	HistoricalCoverage uint32 `json:"historical_coverage"`

	SnapshotCoverage uint32 `json:"snapshot_coverage"`
}

type ReportExecutiveSummary struct {
	OverallSeverity string `json:"overall_severity"`

	RiskScore int `json:"risk_score"`

	TopFindingCount uint32 `json:"top_finding_count"`

	HistoricalChainCount uint32 `json:"historical_chain_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	Statement string `json:"statement"`
}

type ReportFinding struct {
	Source string `json:"source"`

	ID string `json:"id"`

	Severity string `json:"severity"`

	Score int `json:"score"`

	Title string `json:"title"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	Object string `json:"object,omitempty"`

	User string `json:"user,omitempty"`

	Reasons []string `json:"reasons,omitempty"`
}

type ReportChainSummary struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Confidence string `json:"confidence"`

	Score int `json:"score"`

	StartTime time.Time `json:"start_time,omitempty"`

	EndTime time.Time `json:"end_time,omitempty"`

	Summary string `json:"summary"`

	Reasons []string `json:"reasons,omitempty"`
}

type ReportTimelineEvent struct {
	Timestamp time.Time `json:"timestamp,omitempty"`

	Category string `json:"category"`

	Type string `json:"type"`

	User string `json:"user,omitempty"`

	Process string `json:"process,omitempty"`

	Object string `json:"object,omitempty"`

	Description string `json:"description"`
}
