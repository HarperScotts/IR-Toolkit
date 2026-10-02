package model

type FileFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Title string `json:"title"`

	Path string `json:"path"`

	SHA256 string `json:"sha256,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	Executed bool `json:"executed"`

	RelatedPIDs []uint32 `json:"related_pids,omitempty"`

	RelatedProcesses []string `json:"related_processes,omitempty"`

	Persistence []string `json:"persistence,omitempty"`

	ExternalConnections []NetworkConnection `json:"external_connections,omitempty"`
}

type FileAnalysisStatistics struct {
	FileCount uint32 `json:"file_count"`

	ExecutableCount uint32 `json:"executable_count"`

	ExecutedFileCount uint32 `json:"executed_file_count"`

	PersistenceReferencedCount uint32 `json:"persistence_referenced_count"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type FileAnalysis struct {
	Findings []FileFinding `json:"findings"`

	Statistics FileAnalysisStatistics `json:"statistics"`
}
