package model

import "time"

type LinuxLogin1Analysis struct {
	Profile      string                   `json:"profile"`
	Status       string                   `json:"status"`
	SourceStatus string                   `json:"source_status"`
	StartedAt    time.Time                `json:"started_at"`
	CompletedAt  time.Time                `json:"completed_at"`
	BootID       string                   `json:"boot_id,omitempty"`
	BusID        string                   `json:"bus_id,omitempty"`
	ServiceOwner string                   `json:"service_owner,omitempty"`
	ListSHA256   string                   `json:"list_sha256,omitempty"`
	Observations []LinuxLogin1Observation `json:"observations"`
	Warnings     []string                 `json:"warnings"`
}

type LinuxLogin1Observation struct {
	ID             string                `json:"id"`
	Session        LinuxLogin1Session    `json:"session"`
	PropertyStatus string                `json:"property_status"`
	Properties     LinuxLogin1Properties `json:"properties"`
	SourceCall     *LinuxLogin1Call      `json:"source_call,omitempty"`
	Warnings       []string              `json:"warnings"`
}

// Pointers distinguish absence/invalid values from reported false, zero or an
// empty string. These remain service claims, not verified current identities.
type LinuxLogin1Properties struct {
	State       *string `json:"state"`
	Active      *bool   `json:"active"`
	Remote      *bool   `json:"remote"`
	Leader      *uint32 `json:"reported_leader_pid"`
	Type        *string `json:"type"`
	Class       *string `json:"class"`
	TTY         *string `json:"tty"`
	Service     *string `json:"service"`
	RemoteHost  *string `json:"remote_host"`
	RemoteUser  *string `json:"remote_user"`
	TimestampUS *uint64 `json:"reported_creation_usec,string"` // decimal string avoids browser float64 rounding
}
