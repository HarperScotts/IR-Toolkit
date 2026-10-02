package model

type CapabilityStatus struct {
	Available bool `json:"available"`

	Enabled bool `json:"enabled"`

	Status string `json:"status"`

	Reason string `json:"reason,omitempty"`
}

type AuditCapabilitySnapshot struct {
	SecurityLog CapabilityStatus `json:"security_log"`

	LogonAudit CapabilityStatus `json:"logon_audit"`

	ProcessCreationAudit CapabilityStatus `json:"process_creation_audit"`

	ProcessCreationEvents CapabilityStatus `json:"process_creation_events"`

	PowerShellOperational CapabilityStatus `json:"powershell_operational"`

	PowerShellScriptBlockLogging CapabilityStatus `json:"powershell_script_block_logging"`

	DefenderOperational CapabilityStatus `json:"defender_operational"`

	Sysmon CapabilityStatus `json:"sysmon"`

	CollectionMode string `json:"collection_mode"`

	HistoricalCoverage uint32 `json:"historical_coverage"`

	SnapshotCoverage uint32 `json:"snapshot_coverage"`

	Warnings []string `json:"warnings,omitempty"`
}
