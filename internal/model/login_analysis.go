package model

import "time"

type LoginFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Title string `json:"title"`

	Timestamp time.Time `json:"timestamp"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	LogonType uint32 `json:"logon_type,omitempty"`

	LogonTypeName string `json:"logon_type_name,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	RelatedEvents []uint32 `json:"related_events,omitempty"`

	RelatedPIDs []uint32 `json:"related_pids,omitempty"`
}

type LoginSessionAnalysis struct {
	LogonID string `json:"logon_id"`

	Timestamp time.Time `json:"timestamp"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	SourcePort string `json:"source_port,omitempty"`

	Workstation string `json:"workstation,omitempty"`

	LogonType uint32 `json:"logon_type,omitempty"`

	LogonTypeName string `json:"logon_type_name,omitempty"`

	AuthenticationPackage string `json:"authentication_package,omitempty"`

	Privileged bool `json:"privileged"`

	Privileges string `json:"privileges,omitempty"`

	Events []uint32 `json:"events,omitempty"`

	Processes []LoginProcessRef `json:"processes,omitempty"`

	ProcessCount uint32 `json:"process_count"`

	ProcessesWithNetwork uint32 `json:"processes_with_network"`

	ProcessesWithExternalNetwork uint32 `json:"processes_with_external_network"`
}

type FailedLoginGroup struct {
	SourceIP string `json:"source_ip,omitempty"`

	User string `json:"user,omitempty"`

	Count uint32 `json:"count"`

	FirstSeen time.Time `json:"first_seen"`

	LastSeen time.Time `json:"last_seen"`

	LogonTypes []uint32 `json:"logon_types,omitempty"`
}

type LoginAnalysisStatistics struct {
	SessionCount uint32 `json:"session_count"`

	RemoteInteractiveCount uint32 `json:"remote_interactive_count"`

	NetworkLogonCount uint32 `json:"network_logon_count"`

	PrivilegedSessionCount uint32 `json:"privileged_session_count"`

	ExplicitCredentialCount uint32 `json:"explicit_credential_count"`

	FailedLoginCount uint32 `json:"failed_login_count"`

	FailedLoginGroupCount uint32 `json:"failed_login_group_count"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type LoginAnalysis struct {
	Sessions []LoginSessionAnalysis `json:"sessions"`

	FailedLoginGroups []FailedLoginGroup `json:"failed_login_groups,omitempty"`

	Findings []LoginFinding `json:"findings"`

	Statistics LoginAnalysisStatistics `json:"statistics"`
}

type LoginProcessRef struct {
	PID uint32 `json:"pid"`

	PPID uint32 `json:"ppid,omitempty"`

	Name string `json:"name"`

	Path string `json:"path,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`

	StartTime string `json:"start_time,omitempty"`

	HasNetwork bool `json:"has_network"`

	ExternalConnections []NetworkConnection `json:"external_connections,omitempty"`
}
