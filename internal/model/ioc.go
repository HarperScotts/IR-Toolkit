package model

type IOCFile struct {
	Version int `yaml:"version" json:"version"`

	Metadata IOCMetadata `yaml:"metadata" json:"metadata"`

	IOCs IOCSet `yaml:"iocs" json:"iocs"`
}

type IOCMetadata struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`

	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	Source string `yaml:"source,omitempty" json:"source,omitempty"`

	CreatedAt string `yaml:"created_at,omitempty" json:"created_at,omitempty"`
}

type IOCSet struct {
	Hashes []IOCValue `yaml:"hashes,omitempty" json:"hashes,omitempty"`

	IPs []IOCValue `yaml:"ips,omitempty" json:"ips,omitempty"`

	Domains []IOCValue `yaml:"domains,omitempty" json:"domains,omitempty"`

	Paths []IOCValue `yaml:"paths,omitempty" json:"paths,omitempty"`

	ProcessNames []IOCValue `yaml:"process_names,omitempty" json:"process_names,omitempty"`

	CommandLines []IOCValue `yaml:"command_lines,omitempty" json:"command_lines,omitempty"`
}

type IOCValue struct {
	Value string `yaml:"value" json:"value"`

	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	Match string `yaml:"match,omitempty" json:"match,omitempty"`
}

type IOCMatch struct {
	IOCType string `json:"ioc_type"`

	IOCValue string `json:"ioc_value"`

	Description string `json:"description,omitempty"`

	MatchType string `json:"match_type"`

	Source string `json:"source"`

	Object string `json:"object"`

	PID uint32 `json:"pid,omitempty"`

	Process string `json:"process,omitempty"`

	Path string `json:"path,omitempty"`

	SHA256 string `json:"sha256,omitempty"`

	RemoteAddress string `json:"remote_address,omitempty"`

	RemotePort uint32 `json:"remote_port,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	PersistenceType string `json:"persistence_type,omitempty"`

	PersistenceName string `json:"persistence_name,omitempty"`

	RelatedID string `json:"related_id,omitempty"`
}

type IOCScanStatistics struct {
	IOCCount uint32 `json:"ioc_count"`

	MatchCount uint32 `json:"match_count"`

	HashMatches uint32 `json:"hash_matches"`

	IPMatches uint32 `json:"ip_matches"`

	DomainMatches uint32 `json:"domain_matches"`

	PathMatches uint32 `json:"path_matches"`

	ProcessNameMatches uint32 `json:"process_name_matches"`

	CommandLineMatches uint32 `json:"command_line_matches"`
}

type IOCScanResult struct {
	Matches []IOCMatch `json:"matches"`

	Statistics IOCScanStatistics `json:"statistics"`
}
