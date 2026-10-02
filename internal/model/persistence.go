package model

import "time"

type PersistenceSnapshot struct {
	Services       []ServiceInfo      `json:"services"`
	RunKeys        []RegistryRunEntry `json:"run_keys"`
	ScheduledTasks []ScheduledTask    `json:"scheduled_tasks"`

	Warnings []string `json:"warnings,omitempty"`
}

// --------------------------------------------------
// Windows Service
// --------------------------------------------------

type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`

	BinaryPath string `json:"binary_path,omitempty"`

	StartType string `json:"start_type,omitempty"`

	Account string `json:"account,omitempty"`

	State string `json:"state,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	ServiceType uint32 `json:"service_type,omitempty"`

	DelayedAutoStart bool `json:"delayed_auto_start,omitempty"`

	Errors []string `json:"errors,omitempty"`
}

// --------------------------------------------------
// Registry Run Key
// --------------------------------------------------

type RegistryRunEntry struct {
	Hive string `json:"hive"`

	Key string `json:"key"`

	View string `json:"view,omitempty"`

	Name string `json:"name"`

	Command string `json:"command"`

	ExpandedCommand string `json:"expanded_command,omitempty"`

	ValueType string `json:"value_type,omitempty"`

	KeyModifiedAt time.Time `json:"key_modified_at,omitempty"`

	ReadError string `json:"read_error,omitempty"`
}

// --------------------------------------------------
// Scheduled Task
// --------------------------------------------------

type ScheduledTaskAction struct {
	Command string `json:"command,omitempty"`

	Arguments string `json:"arguments,omitempty"`

	WorkingDirectory string `json:"working_directory,omitempty"`
}

type ScheduledTask struct {
	Name string `json:"name"`

	Path string `json:"path"`

	FilePath string `json:"file_path,omitempty"`

	Author string `json:"author,omitempty"`

	Description string `json:"description,omitempty"`

	UserID string `json:"user_id,omitempty"`

	LogonType string `json:"logon_type,omitempty"`

	RunLevel string `json:"run_level,omitempty"`

	Enabled *bool `json:"enabled,omitempty"`

	Hidden *bool `json:"hidden,omitempty"`

	TriggerTypes []string `json:"trigger_types,omitempty"`

	Actions []ScheduledTaskAction `json:"actions,omitempty"`

	ModifiedAt time.Time `json:"modified_at,omitempty"`

	ParseError string `json:"parse_error,omitempty"`
}
