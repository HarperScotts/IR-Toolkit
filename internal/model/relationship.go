package model

type ProcessRef struct {
	PID uint32 `json:"pid"`

	Name string `json:"name"`

	Path string `json:"path,omitempty"`
}

type ProcessRelationship struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`

	Name string `json:"name"`

	Path string `json:"path,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`

	Parent *ProcessRef `json:"parent,omitempty"`

	Children []ProcessRef `json:"children,omitempty"`

	Connections []NetworkConnection `json:"connections,omitempty"`

	ExternalConnections []NetworkConnection `json:"external_connections,omitempty"`

	Indicators []string `json:"indicators,omitempty"`
}

type RelationshipFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Indicator string `json:"indicator"`

	Title string `json:"title"`

	PID uint32 `json:"pid"`

	RelatedPIDs []uint32 `json:"related_pids,omitempty"`

	Evidence []string `json:"evidence,omitempty"`
}

type ProcessRelationshipStatistics struct {
	ProcessCount uint32 `json:"process_count"`

	ParentChildRelations uint32 `json:"parent_child_relations"`

	ProcessesWithExternalNetwork uint32 `json:"processes_with_external_network"`

	Findings uint32 `json:"findings"`
}

type ProcessRelationshipAnalysis struct {
	Processes []ProcessRelationship `json:"processes"`

	Findings []RelationshipFinding `json:"findings"`

	Statistics ProcessRelationshipStatistics `json:"statistics"`
}
