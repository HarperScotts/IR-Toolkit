package model

import "time"

type LoginStatistics struct {
	SessionCount uint32 `json:"session_count"`

	EventCount uint32 `json:"event_count"`

	SuccessfulLogons uint32 `json:"successful_logons"`

	FailedLogons uint32 `json:"failed_logons"`

	ExplicitCredentialEvents uint32 `json:"explicit_credential_events"`

	PrivilegedLogons uint32 `json:"privileged_logons"`
}

type LoginSnapshot struct {
	Sessions []LoginSession `json:"sessions"`

	Events []LoginEvent `json:"events"`

	Statistics LoginStatistics `json:"statistics"`

	Warnings []string `json:"warnings,omitempty"`
}

type LoginSession struct {
	SessionID uint32 `json:"session_id"`

	StationName string `json:"station_name,omitempty"`

	State string `json:"state,omitempty"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	ClientName string `json:"client_name,omitempty"`

	ClientAddress string `json:"client_address,omitempty"`
}

type LoginEvent struct {
	EventID uint32 `json:"event_id"`

	Timestamp time.Time `json:"timestamp"`

	Computer string `json:"computer,omitempty"`

	Success bool `json:"success"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	SourcePort string `json:"source_port,omitempty"`

	Workstation string `json:"workstation,omitempty"`

	LogonType uint32 `json:"logon_type,omitempty"`

	LogonTypeName string `json:"logon_type_name,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	AuthenticationPackage string `json:"authentication_package,omitempty"`

	TargetLogonID string `json:"target_logon_id,omitempty"`

	Status string `json:"status,omitempty"`

	SubStatus string `json:"sub_status,omitempty"`

	Privileges string `json:"privileges,omitempty"`

	// 保存原始 EventData，避免标准化时丢失信息。
	Data map[string]string `json:"data,omitempty"`
}
