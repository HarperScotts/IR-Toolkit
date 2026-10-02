package model

import "time"

type HostInfo struct {
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	OSVersion    string   `json:"os_version,omitempty"`
	Architecture string   `json:"architecture"`

	Kernel string `json:"kernel,omitempty"`

	CPUCount    int    `json:"cpu_count"`
	MemoryBytes uint64 `json:"memory_bytes"`

	BootTime time.Time `json:"boot_time,omitempty"`

	CurrentUser string `json:"current_user,omitempty"`

	IPAddresses  []string `json:"ip_addresses,omitempty"`
	MACAddresses []string `json:"mac_addresses,omitempty"`

	DNS     []string `json:"dns,omitempty"`
	Gateway []string `json:"gateway,omitempty"`
}