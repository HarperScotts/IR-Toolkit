package model

import "time"

type PowerShellEventSnapshot struct {
	Events []PowerShellEvent `json:"events"`

	Warnings []string `json:"warnings,omitempty"`

	Statistics PowerShellEventStatistics `json:"statistics"`
}

type PowerShellEventStatistics struct {
	EventCount uint32 `json:"event_count"`

	ModuleLoggingCount uint32 `json:"module_logging_count"`

	ScriptBlockCount uint32 `json:"script_block_count"`

	ScriptTextCount uint32 `json:"script_text_count"`
}

type PowerShellEvent struct {
	EventID uint32 `json:"event_id"`

	Timestamp time.Time `json:"timestamp"`

	Computer string `json:"computer,omitempty"`

	Provider string `json:"provider,omitempty"`

	Level uint32 `json:"level,omitempty"`

	RecordID uint64 `json:"record_id,omitempty"`

	ActivityID string `json:"activity_id,omitempty"`

	ProcessID uint32 `json:"process_id,omitempty"`

	ThreadID uint32 `json:"thread_id,omitempty"`

	ScriptBlockID string `json:"script_block_id,omitempty"`

	ScriptBlockText string `json:"script_block_text,omitempty"`

	MessageNumber uint32 `json:"message_number,omitempty"`

	MessageTotal uint32 `json:"message_total,omitempty"`

	Path string `json:"path,omitempty"`

	CommandName string `json:"command_name,omitempty"`

	CommandType string `json:"command_type,omitempty"`

	HostApplication string `json:"host_application,omitempty"`

	ContextInfo string `json:"context_info,omitempty"`

	UserData string `json:"user_data,omitempty"`

	Payload string `json:"payload,omitempty"`

	Data map[string]string `json:"data,omitempty"`
}
