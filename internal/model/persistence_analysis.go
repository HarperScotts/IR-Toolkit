package model

type PersistenceFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Name string `json:"name"`

	Title string `json:"title"`

	Command string `json:"command,omitempty"`

	ExecutablePath string `json:"executable_path,omitempty"`

	User string `json:"user,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	RelatedPID uint32 `json:"related_pid,omitempty"`

	RelatedProcess string `json:"related_process,omitempty"`

	ExternalConnections []NetworkConnection `json:"external_connections,omitempty"`
}

type PersistenceAnalysisStatistics struct {
	ServiceCount uint32 `json:"service_count"`

	RunKeyCount uint32 `json:"run_key_count"`

	ScheduledTaskCount uint32 `json:"scheduled_task_count"`

	AnalyzedActions uint32 `json:"analyzed_actions"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type PersistenceAnalysis struct {
	Findings []PersistenceFinding `json:"findings"`

	Statistics PersistenceAnalysisStatistics `json:"statistics"`
}
