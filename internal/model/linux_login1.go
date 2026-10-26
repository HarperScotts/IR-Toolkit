package model

import "time"

// These are raw login1 service observations, not authenticated sessions,
// process identities, SSH outcomes or historical login reconstruction.
type LinuxLogin1Snapshot struct {
	Status       string               `json:"status"` // observed_subset, partial, error, unsupported
	StartedAt    time.Time            `json:"started_at"`
	CompletedAt  time.Time            `json:"completed_at"`
	BusAddress   string               `json:"bus_address"`
	Executable   string               `json:"executable"`
	BootID       string               `json:"boot_id,omitempty"`
	ServiceOwner string               `json:"service_owner,omitempty"`
	BusID        string               `json:"bus_id,omitempty"`
	Sessions     []LinuxLogin1Session `json:"sessions"`
	Calls        []LinuxLogin1Call    `json:"calls"`
	Warnings     []string             `json:"warnings"`
}

type LinuxLogin1Session struct {
	SessionID      string `json:"session_id"`
	ReportedUID    uint32 `json:"reported_uid"`
	ReportedUser   string `json:"reported_user"`
	ReportedSeat   string `json:"reported_seat"`
	ObjectPath     string `json:"object_path"`
	PropertiesCall int    `json:"properties_call"` // index into Calls, -1 if not read
}

type LinuxLogin1Call struct {
	Destination string    `json:"destination"`
	ObjectPath  string    `json:"object_path"`
	Interface   string    `json:"interface"`
	Method      string    `json:"method"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Status      string    `json:"status"`            // observed, error
	Content     []byte    `json:"content,omitempty"` // original busctl JSON stdout, not D-Bus wire bytes
	SHA256      string    `json:"sha256,omitempty"`
	Stderr      []byte    `json:"stderr,omitempty"`
	Error       string    `json:"error,omitempty"`
}
