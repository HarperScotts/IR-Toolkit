package model

import "time"

type FileTriageSnapshot struct {
	Files []FileTriageItem `json:"files"`

	ScannedRoots []string `json:"scanned_roots"`

	Warnings []string `json:"warnings,omitempty"`

	Statistics FileTriageStatistics `json:"statistics"`
}

type FileTriageStatistics struct {
	RootCount uint32 `json:"root_count"`

	FileCount uint32 `json:"file_count"`

	HashedCount uint32 `json:"hashed_count"`

	ExecutableCount uint32 `json:"executable_count"`

	ADSCount uint32 `json:"ads_count"`
}

type FileTriageItem struct {
	Path string `json:"path"`

	Name string `json:"name"`

	Extension string `json:"extension,omitempty"`

	Size int64 `json:"size"`

	CreatedAt time.Time `json:"created_at,omitempty"`

	ModifiedAt time.Time `json:"modified_at,omitempty"`

	AccessedAt time.Time `json:"accessed_at,omitempty"`

	Owner string `json:"owner,omitempty"`

	Executable bool `json:"executable"`

	SHA256 string `json:"sha256,omitempty"`

	ADS []AlternateDataStream `json:"ads,omitempty"`

	ZoneIdentifier string `json:"zone_identifier,omitempty"`

	Source string `json:"source"`
}

type AlternateDataStream struct {
	Name string `json:"name"`

	Size int64 `json:"size,omitempty"`
}
