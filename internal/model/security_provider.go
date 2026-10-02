package model

type SecurityProviderSnapshot struct {
	Providers []SecurityProvider `json:"providers"`

	EventChannels []SecurityEventChannel `json:"event_channels,omitempty"`

	Statistics SecurityProviderStatistics `json:"statistics"`

	Warnings []string `json:"warnings,omitempty"`
}

type SecurityProvider struct {
	ID string `json:"id"`

	Name string `json:"name"`

	Type string `json:"type"`

	ProductState uint32 `json:"product_state,omitempty"`

	ProductStateHex string `json:"product_state_hex,omitempty"`

	ProductExecutable string `json:"product_executable,omitempty"`

	ReportingExecutable string `json:"reporting_executable,omitempty"`

	Registered bool `json:"registered"`

	Source string `json:"source"`

	Services []SecurityProviderService `json:"services,omitempty"`

	EventChannels []string `json:"event_channels,omitempty"`
}

type SecurityProviderService struct {
	Name string `json:"name"`

	DisplayName string `json:"display_name,omitempty"`

	State string `json:"state,omitempty"`

	ImagePath string `json:"image_path,omitempty"`
}

type SecurityEventChannel struct {
	Name string `json:"name"`

	Provider string `json:"provider,omitempty"`

	Available bool `json:"available"`

	Enabled bool `json:"enabled"`

	Category string `json:"category,omitempty"`
}

type SecurityProviderStatistics struct {
	ProviderCount uint32 `json:"provider_count"`

	AntivirusCount uint32 `json:"antivirus_count"`

	AntispywareCount uint32 `json:"antispyware_count"`

	FirewallCount uint32 `json:"firewall_count"`

	SecurityServiceCount uint32 `json:"security_service_count"`

	EventChannelCount uint32 `json:"event_channel_count"`
}
