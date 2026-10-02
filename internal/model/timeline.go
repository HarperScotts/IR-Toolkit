package model

import "time"

type TimelineEvent struct {
	ID string `json:"id"`

	Timestamp time.Time `json:"timestamp"`

	Type string `json:"type"`

	Category string `json:"category"`

	Severity string `json:"severity,omitempty"`

	Host string `json:"host,omitempty"`

	User string `json:"user,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	PPID uint32 `json:"ppid,omitempty"`

	Process string `json:"process,omitempty"`

	Object string `json:"object,omitempty"`

	Description string `json:"description"`

	LogonID string `json:"logon_id,omitempty"`

	RelatedIDs []string `json:"related_ids,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type TimelineStatistics struct {
	EventCount uint32 `json:"event_count"`

	LoginEvents uint32 `json:"login_events"`

	ProcessEvents uint32 `json:"process_events"`

	NetworkEvents uint32 `json:"network_events"`

	PersistenceEvents uint32 `json:"persistence_events"`

	CriticalEvents uint32 `json:"critical_events"`

	HighEvents uint32 `json:"high_events"`

	MediumEvents uint32 `json:"medium_events"`

	HistoricalProcessEvents uint32 `json:"historical_process_events"`

	PowerShellEvents uint32 `json:"powershell_events"`

	CategoryCounts map[string]uint32 `json:"category_counts,omitempty"`
}

type Timeline struct {
	Events []TimelineEvent `json:"events"`

	Statistics TimelineStatistics `json:"statistics"`
}
