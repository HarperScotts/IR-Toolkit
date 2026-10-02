package model

type ProcessNetworkAnalysis struct {
	PID uint32 `json:"pid"`

	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	SessionID        uint32 `json:"session_id,omitempty"`
	AuthenticationID string `json:"authentication_id,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`

	StartTime string `json:"start_time,omitempty"`

	Connections []NetworkConnection `json:"connections"`

	Listeners []NetworkConnection `json:"listeners"`

	ExternalConnections []NetworkConnection `json:"external_connections"`

	Indicators []string `json:"indicators,omitempty"`
}

type NetworkAnalysis struct {
	Processes []ProcessNetworkAnalysis `json:"processes"`

	OrphanConnections []NetworkConnection `json:"orphan_connections,omitempty"`

	Statistics NetworkAnalysisStatistics `json:"statistics"`
}

type NetworkAnalysisStatistics struct {
	ProcessCount uint32 `json:"process_count"`

	ProcessWithNetwork uint32 `json:"process_with_network"`

	ConnectionCount uint32 `json:"connection_count"`

	TCPCount uint32 `json:"tcp_count"`

	UDPCount uint32 `json:"udp_count"`

	ListenerCount uint32 `json:"listener_count"`

	ExternalConnectionCount uint32 `json:"external_connection_count"`
}
