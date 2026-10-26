package model

import "time"

// Linux login evidence is deliberately separate from Windows events/sessions.
type LinuxLoginArtifact struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"` // observed, missing, error, not_scanned
	Mode       string    `json:"mode,omitempty"`
	UID        *uint32   `json:"uid,omitempty"`
	GID        *uint32   `json:"gid,omitempty"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modified_at,omitempty"`
	Content    []byte    `json:"content,omitempty"`
	SHA256     string    `json:"sha256,omitempty"`
	LinkTarget string    `json:"link_target,omitempty"`
	ReadError  string    `json:"read_error,omitempty"`
}

// A log-reported authentication outcome, not a reconstructed session or proof
// of execution. ReportedPID is source text, never a current process identity.
type LinuxLoginRecord struct {
	ID                  string    `json:"id"`
	SourcePath          string    `json:"source_path"`
	SourceSHA256        string    `json:"source_sha256"`
	Line                int       `json:"line"`
	RawLine             string    `json:"raw_line"`
	Timestamp           time.Time `json:"timestamp"`
	TimestampRaw        string    `json:"timestamp_raw"`
	TimeBasis           string    `json:"time_basis"` // explicit_offset or unknown
	ReportedHost        string    `json:"reported_host"`
	Program             string    `json:"program"`
	ReportedPID         string    `json:"reported_pid,omitempty"`
	Outcome             string    `json:"outcome"` // accepted or failed, as reported by the log
	Method              string    `json:"method"`
	User                string    `json:"user"`
	InvalidUserReported bool      `json:"invalid_user_reported,omitempty"`
	SourceIP            string    `json:"source_ip"`
	SourcePort          uint32    `json:"source_port"`
}

type LinuxLoginParseSource struct {
	Path         string   `json:"path"`
	SHA256       string   `json:"sha256,omitempty"`
	Status       string   `json:"status"` // observed_subset, partial, skipped
	RecordCount  uint32   `json:"record_count"`
	IgnoredLines uint32   `json:"ignored_lines"`
	Warnings     []string `json:"warnings,omitempty"`
}

type LinuxLoginStatistics struct {
	RecordCount      uint32 `json:"record_count"`
	ReportedAccepted uint32 `json:"reported_accepted"`
	ReportedFailed   uint32 `json:"reported_failed"`
	UnknownTimeCount uint32 `json:"unknown_time_count"`
}
