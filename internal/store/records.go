package store

import "time"

type ProcessHistoryRecord struct {
	Processes []HistoricalProcessRecord `json:"processes"`
}

type HistoricalProcessRecord struct {
	ID                 string    `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	PID                uint32    `json:"pid"`
	ParentPID          uint32    `json:"parent_pid"`
	ProcessName        string    `json:"process_name"`
	ProcessPath        string    `json:"process_path"`
	CommandLine        string    `json:"command_line,omitempty"`
	ParentProcessName  string    `json:"parent_process_name,omitempty"`
	User               string    `json:"user,omitempty"`
	Domain             string    `json:"domain,omitempty"`
	LogonID            string    `json:"logon_id,omitempty"`
	TokenElevationType string    `json:"token_elevation_type,omitempty"`
	MandatoryLabel     string    `json:"mandatory_label,omitempty"`
	MatchedLogin       bool      `json:"matched_login"`
	CurrentProcess     bool      `json:"current_process"`
	CurrentProcessPath string    `json:"current_process_path,omitempty"`
}

type CorrelationEvidenceRecord struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

type CorrelationEdgeRecord struct {
	ID         string                      `json:"id"`
	From       string                      `json:"from"`
	To         string                      `json:"to"`
	Type       string                      `json:"type"`
	Confidence string                      `json:"confidence,omitempty"`
	Score      int                         `json:"score,omitempty"`
	Basis      []CorrelationEvidenceRecord `json:"basis,omitempty"`
	Timestamp  time.Time                   `json:"timestamp,omitempty"`
}

type CorrelationNodeRecord struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Label     string            `json:"label"`
	Timestamp time.Time         `json:"timestamp,omitempty"`
	User      string            `json:"user,omitempty"`
	LogonID   string            `json:"logon_id,omitempty"`
	PID       uint32            `json:"pid,omitempty"`
	Object    string            `json:"object,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type HistoricalChainRecord struct {
	ID         string    `json:"id"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Score      int       `json:"score"`
	Confidence string    `json:"confidence"`
	StartTime  time.Time `json:"start_time,omitempty"`
	EndTime    time.Time `json:"end_time,omitempty"`
	NodeIDs    []string  `json:"node_ids"`
	EdgeIDs    []string  `json:"edge_ids"`
	Reasons    []string  `json:"reasons,omitempty"`
	Summary    string    `json:"summary,omitempty"`
}

type HistoricalCorrelationRecord struct {
	Nodes  []CorrelationNodeRecord `json:"nodes,omitempty"`
	Edges  []CorrelationEdgeRecord `json:"edges,omitempty"`
	Chains []HistoricalChainRecord `json:"chains,omitempty"`
}

type NetworkAnalysisRecord struct {
	Processes []ProcessNetworkRecord `json:"processes"`
}

type ProcessNetworkRecord struct {
	PID                 uint32                    `json:"pid"`
	ProcessName         string                    `json:"process_name,omitempty"`
	ProcessPath         string                    `json:"process_path,omitempty"`
	User                string                    `json:"user,omitempty"`
	SessionID           uint32                    `json:"session_id,omitempty"`
	AuthenticationID    string                    `json:"authentication_id,omitempty"`
	IntegrityLevel      string                    `json:"integrity_level,omitempty"`
	StartTime           time.Time                 `json:"start_time,omitempty"`
	Connections         []NetworkConnectionRecord `json:"connections,omitempty"`
	Listeners           []NetworkConnectionRecord `json:"listeners,omitempty"`
	ExternalConnections []NetworkConnectionRecord `json:"external_connections,omitempty"`
}

type NetworkConnectionRecord struct {
	PID           uint32 `json:"pid"`
	ProcessName   string `json:"process_name,omitempty"`
	ProcessPath   string `json:"process_path,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	Family        string `json:"family,omitempty"`
	LocalAddress  string `json:"local_address,omitempty"`
	LocalPort     uint32 `json:"local_port,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint32 `json:"remote_port,omitempty"`
	State         string `json:"state,omitempty"`
}
