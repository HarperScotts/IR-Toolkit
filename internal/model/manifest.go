package model

import "time"

type EvidenceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	CaseID          string         `json:"case_id"`
	ToolVersion     string         `json:"tool_version"`
	Hostname        string         `json:"hostname"`
	Platform        string         `json:"platform"`
	Architecture    string         `json:"architecture"`
	StartedAt       time.Time      `json:"started_at"`
	FinishedAt      time.Time      `json:"finished_at"`
	Files           []EvidenceFile `json:"files"`
	CollectionSince *time.Time     `json:"collection_since,omitempty"`

	CollectionUntil *time.Time `json:"collection_until,omitempty"`
}
