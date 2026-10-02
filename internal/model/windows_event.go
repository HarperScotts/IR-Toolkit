package model

import "time"

type WindowsEventSnapshot struct {
	Definitions []WindowsEventDefinitionResult `json:"definitions"`

	Events []WindowsEvent `json:"events"`

	Warnings []string `json:"warnings,omitempty"`

	Statistics WindowsEventStatistics `json:"statistics"`
}

type WindowsEventDefinitionResult struct {
	ID string `json:"id"`

	Channel string `json:"channel"`

	RequestedEventIDs []uint32 `json:"requested_event_ids"`

	EventCount uint32 `json:"event_count"`

	Status string `json:"status"`

	Warning string `json:"warning,omitempty"`
}

type WindowsEvent struct {
	DefinitionID string `json:"definition_id"`

	Channel string `json:"channel"`

	Provider string `json:"provider,omitempty"`

	EventID uint32 `json:"event_id"`

	RecordID uint64 `json:"record_id,omitempty"`

	Level uint32 `json:"level,omitempty"`

	Timestamp time.Time `json:"timestamp"`

	Computer string `json:"computer,omitempty"`

	ProcessID uint32 `json:"process_id,omitempty"`

	ThreadID uint32 `json:"thread_id,omitempty"`

	ActivityID string `json:"activity_id,omitempty"`

	UserID string `json:"user_id,omitempty"`

	Data map[string]string `json:"data,omitempty"`

	Message string `json:"message,omitempty"`

	UserData map[string]string `json:"user_data,omitempty"`
}

type WindowsEventStatistics struct {
	DefinitionCount uint32 `json:"definition_count"`

	EnabledDefinitionCount uint32 `json:"enabled_definition_count"`

	EventCount uint32 `json:"event_count"`

	WarningCount uint32 `json:"warning_count"`
}
