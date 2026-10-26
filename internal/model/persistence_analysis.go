package model

type PersistenceFinding struct {
	ID string `json:"id"`

	Severity string `json:"severity"`

	Type string `json:"type"`

	Name string `json:"name"`

	Title string `json:"title"`

	Command string `json:"command,omitempty"`

	ExecutablePath string `json:"executable_path,omitempty"`

	User string `json:"user,omitempty"`

	Score int `json:"score"`

	Reasons []string `json:"reasons"`

	RelatedPID uint32 `json:"related_pid,omitempty"`

	RelatedProcess string `json:"related_process,omitempty"`

	ExternalConnections []NetworkConnection `json:"external_connections,omitempty"`
}

type PersistenceAnalysisStatistics struct {
	LinuxSystemdMergeCount   uint32 `json:"linux_systemd_merge_count,omitempty"`
	LinuxSystemdBlockedCount uint32 `json:"linux_systemd_blocked_count,omitempty"`
	LinuxConfigCount         uint32 `json:"linux_config_count,omitempty"`
	LinuxDirectiveCount      uint32 `json:"linux_directive_count,omitempty"`
	LinuxCronEntryCount      uint32 `json:"linux_cron_entry_count,omitempty"`
	LinuxArtifactCount       uint32 `json:"linux_artifact_count,omitempty"`
	LinuxReadErrorCount      uint32 `json:"linux_read_error_count,omitempty"`
	ServiceCount             uint32 `json:"service_count"`

	RunKeyCount uint32 `json:"run_key_count"`

	ScheduledTaskCount uint32 `json:"scheduled_task_count"`

	AnalyzedActions uint32 `json:"analyzed_actions"`

	FindingCount uint32 `json:"finding_count"`

	CriticalCount uint32 `json:"critical_count"`

	HighCount uint32 `json:"high_count"`

	MediumCount uint32 `json:"medium_count"`

	LowCount uint32 `json:"low_count"`
}

type PersistenceAnalysis struct {
	LinuxSystemdMerges []LinuxSystemdMerge      `json:"linux_systemd_merges,omitempty"`
	LinuxConfigs       []LinuxPersistenceConfig `json:"linux_configs,omitempty"`
	Warnings           []string                 `json:"warnings,omitempty"`
	Findings           []PersistenceFinding     `json:"findings"`

	Statistics PersistenceAnalysisStatistics `json:"statistics"`
}

// Conditional configuration projection within an explicitly observed profile,
// never a statement about the manager's actual load path or runtime state.
type LinuxSystemdMerge struct {
	NameKind    string                    `json:"name_kind,omitempty"` // plain, template_definition, instance
	Template    string                    `json:"template,omitempty"`
	Instance    string                    `json:"instance,omitempty"`
	BaseLookup  string                    `json:"base_lookup,omitempty"` // exact, template_definition, template_fallback
	Unit        string                    `json:"unit"`
	Scope       string                    `json:"scope"`
	Profile     string                    `json:"profile"`
	InputDigest string                    `json:"input_digest"`
	Status      string                    `json:"status"` // observed_subset or blocked
	Activation  string                    `json:"activation"`
	Sources     []LinuxSystemdMergeSource `json:"sources,omitempty"`
	Settings    []LinuxSystemdSetting     `json:"settings,omitempty"`
	Warnings    []string                  `json:"warnings,omitempty"`
}

type LinuxSystemdMergeSource struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
	Role       string `json:"role"`
	Decision   string `json:"decision"` // selected, shadowed, masked_dropin, ambiguous
}

type LinuxSystemdSetting struct {
	Section string              `json:"section"`
	Key     string              `json:"key"`
	Rule    string              `json:"rule"` // last_assignment or append_reset
	Values  []LinuxSystemdValue `json:"values"`
	Resets  []LinuxSystemdValue `json:"resets,omitempty"`
}

type LinuxSystemdValue struct {
	Value   string `json:"value"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Line    int    `json:"line"`
	EndLine int    `json:"end_line"`
}

// File-local syntax only. Activation is always unknown: this does not resolve
// load precedence, daemon state, shell expressions, execution or process links.
type LinuxPersistenceConfig struct {
	Path        string                 `json:"path"`
	Kind        string                 `json:"kind"`
	SHA256      string                 `json:"sha256,omitempty"`
	Format      string                 `json:"format,omitempty"`
	Status      string                 `json:"status"` // observed_syntax, partial, skipped
	Activation  string                 `json:"activation"`
	Directives  []LinuxConfigDirective `json:"directives,omitempty"`
	CronEntries []LinuxCronEntry       `json:"cron_entries,omitempty"`
	Warnings    []string               `json:"warnings,omitempty"`
}

type LinuxConfigDirective struct {
	Line            int    `json:"line"`
	EndLine         int    `json:"end_line"`
	Section         string `json:"section,omitempty"`
	Key             string `json:"key"`
	Value           string `json:"value"`
	EmptyAssignment bool   `json:"empty_assignment,omitempty"`
}

type LinuxCronEntry struct {
	Line         int    `json:"line"`
	Schedule     string `json:"schedule"`
	CommandRaw   string `json:"command_raw"`
	DeclaredUser string `json:"declared_user,omitempty"`
	UserSource   string `json:"user_source,omitempty"` // system_field or spool_filename
}
