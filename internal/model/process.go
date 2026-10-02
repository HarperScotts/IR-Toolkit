package model

import "time"

type Process struct {
	PID  uint32 `json:"pid"`
	PPID uint32 `json:"ppid"`

	Name string `json:"name"`

	Path        string `json:"path,omitempty"`
	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	SessionID        uint32 `json:"session_id,omitempty"`
	AuthenticationID string `json:"authentication_id,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`
	IntegrityRID   uint32 `json:"integrity_rid,omitempty"`

	StartTime time.Time `json:"start_time,omitempty"`

	SHA256 string `json:"sha256,omitempty"`

	Signed bool   `json:"signed,omitempty"`
	Signer string `json:"signer,omitempty"`
}
