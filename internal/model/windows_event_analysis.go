package model

import "time"

type WindowsActivity struct {
	ID string `json:"id"`

	Timestamp time.Time `json:"timestamp"`

	Type string `json:"type"`

	Category string `json:"category"`

	Severity string `json:"severity,omitempty"`

	DefinitionID string `json:"definition_id"`

	Channel string `json:"channel"`

	EventID uint32 `json:"event_id"`

	RecordID uint64 `json:"record_id,omitempty"`

	User string `json:"user,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	SessionID string `json:"session_id,omitempty"`

	ProcessID uint32 `json:"process_id,omitempty"`

	Process string `json:"process,omitempty"`

	Object string `json:"object,omitempty"`

	Description string `json:"description"`

	Reasons []string `json:"reasons,omitempty"`

	RelatedIDs []string `json:"related_ids,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type WindowsEventFinding struct {
	ID string `json:"id"`

	Timestamp time.Time `json:"timestamp"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Title string `json:"title"`

	Score int `json:"score"`

	EventID uint32 `json:"event_id"`

	DefinitionID string `json:"definition_id"`

	User string `json:"user,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	ProcessID uint32 `json:"process_id,omitempty"`

	Object string `json:"object,omitempty"`

	Reasons []string `json:"reasons"`

	RelatedActivityIDs []string `json:"related_activity_ids,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type WindowsEventAnalysisStatistics struct {
	RawEventCount uint32 `json:"raw_event_count"`

	ActivityCount uint32 `json:"activity_count"`

	TaskActivityCount uint32 `json:"task_activity_count"`

	WMIActivityCount uint32 `json:"wmi_activity_count"`

	TerminalServicesActivityCount uint32 `json:"terminal_services_activity_count"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type WindowsEventAnalysis struct {
	Activities []WindowsActivity `json:"activities"`

	Findings []WindowsEventFinding `json:"findings"`

	Statistics WindowsEventAnalysisStatistics `json:"statistics"`
}
