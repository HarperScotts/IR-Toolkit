package model

import "time"

type HistoricalProcess struct {
	ID string `json:"id"`

	Timestamp time.Time `json:"timestamp"`

	PID uint32 `json:"pid"`

	ParentPID uint32 `json:"parent_pid,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	ProcessPath string `json:"process_path,omitempty"`

	ParentProcessName string `json:"parent_process_name,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	TokenElevationType string `json:"token_elevation_type,omitempty"`

	MandatoryLabel string `json:"mandatory_label,omitempty"`

	MatchedLogin bool `json:"matched_login"`

	CurrentProcess bool `json:"current_process"`

	CurrentProcessPath string `json:"current_process_path,omitempty"`
}

type HistoricalProcessEdge struct {
	ParentID string `json:"parent_id"`

	ChildID string `json:"child_id"`

	ParentPID uint32 `json:"parent_pid"`

	ChildPID uint32 `json:"child_pid"`

	Type string `json:"type"`
}

type HistoricalProcessFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Title string `json:"title"`

	Timestamp time.Time `json:"timestamp"`

	PID uint32 `json:"pid,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	RelatedProcessIDs []string `json:"related_process_ids,omitempty"`
}

type ProcessHistoryStatistics struct {
	EventCount uint32 `json:"event_count"`

	HistoricalProcessCount uint32 `json:"historical_process_count"`

	ParentChildEdgeCount uint32 `json:"parent_child_edge_count"`

	MatchedLoginCount uint32 `json:"matched_login_count"`

	MatchedCurrentProcessCount uint32 `json:"matched_current_process_count"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`
}

type ProcessHistoryAnalysis struct {
	Processes []HistoricalProcess `json:"processes"`

	Edges []HistoricalProcessEdge `json:"edges"`

	Findings []HistoricalProcessFinding `json:"findings"`

	Statistics ProcessHistoryStatistics `json:"statistics"`
}
