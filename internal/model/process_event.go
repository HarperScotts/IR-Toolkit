package model

import "time"

type ProcessEventSnapshot struct {
	Events []ProcessEvent `json:"events"`

	Warnings []string `json:"warnings,omitempty"`

	Statistics ProcessEventStatistics `json:"statistics"`
}

type ProcessEventStatistics struct {
	EventCount uint32 `json:"event_count"`

	ProcessCreateCount uint32 `json:"process_create_count"`

	WithCommandLineCount uint32 `json:"with_command_line_count"`
}

type ProcessEvent struct {
	EventID uint32 `json:"event_id"`

	Timestamp time.Time `json:"timestamp"`

	Computer string `json:"computer,omitempty"`

	SubjectUserSID string `json:"subject_user_sid,omitempty"`

	SubjectUserName string `json:"subject_user_name,omitempty"`

	SubjectDomainName string `json:"subject_domain_name,omitempty"`

	SubjectLogonID string `json:"subject_logon_id,omitempty"`

	NewProcessID uint32 `json:"new_process_id,omitempty"`

	NewProcessIDRaw string `json:"new_process_id_raw,omitempty"`

	NewProcessName string `json:"new_process_name,omitempty"`

	TokenElevationType string `json:"token_elevation_type,omitempty"`

	ProcessID uint32 `json:"creator_process_id,omitempty"`

	ProcessIDRaw string `json:"creator_process_id_raw,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	TargetUserSID string `json:"target_user_sid,omitempty"`

	TargetUserName string `json:"target_user_name,omitempty"`

	TargetDomainName string `json:"target_domain_name,omitempty"`

	TargetLogonID string `json:"target_logon_id,omitempty"`

	ParentProcessName string `json:"parent_process_name,omitempty"`

	MandatoryLabel string `json:"mandatory_label,omitempty"`

	Data map[string]string `json:"data,omitempty"`
}
