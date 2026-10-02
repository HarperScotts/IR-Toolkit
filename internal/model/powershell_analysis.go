package model

import "time"

type PowerShellScriptBlock struct {
	ID string `json:"id"`

	ScriptBlockID string `json:"script_block_id"`

	Timestamp time.Time `json:"timestamp"`

	LastTimestamp time.Time `json:"last_timestamp,omitempty"`

	ProcessID uint32 `json:"process_id,omitempty"`

	Path string `json:"path,omitempty"`

	MessageTotal uint32 `json:"message_total,omitempty"`

	FragmentCount uint32 `json:"fragment_count"`

	Complete bool `json:"complete"`

	ScriptText string `json:"script_text"`

	ScriptSHA256 string `json:"script_sha256,omitempty"`

	RelatedHistoricalProcessID string `json:"related_historical_process_id,omitempty"`

	RelatedProcessName string `json:"related_process_name,omitempty"`

	RelatedCommandLine string `json:"related_command_line,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`
}

type PowerShellFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Title string `json:"title"`

	Timestamp time.Time `json:"timestamp"`

	ProcessID uint32 `json:"process_id,omitempty"`

	ScriptBlockID string `json:"script_block_id,omitempty"`

	ScriptSHA256 string `json:"script_sha256,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	Indicators []string `json:"indicators,omitempty"`

	Preview string `json:"preview,omitempty"`
}

type PowerShellAnalysisStatistics struct {
	RawEventCount uint32 `json:"raw_event_count"`

	ScriptBlockEventCount uint32 `json:"script_block_event_count"`

	ModuleEventCount uint32 `json:"module_event_count"`

	ScriptBlockCount uint32 `json:"script_block_count"`

	CompleteScriptBlockCount uint32 `json:"complete_script_block_count"`

	IncompleteScriptBlockCount uint32 `json:"incomplete_script_block_count"`

	MatchedHistoricalProcessCount uint32 `json:"matched_historical_process_count"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type PowerShellAnalysis struct {
	ScriptBlocks []PowerShellScriptBlock `json:"script_blocks"`

	Findings []PowerShellFinding `json:"findings"`

	Statistics PowerShellAnalysisStatistics `json:"statistics"`
}
