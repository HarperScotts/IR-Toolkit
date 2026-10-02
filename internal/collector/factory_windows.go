//go:build windows

package collector

import "ir-toolkit/internal/collector/windows"

func NewHostCollector() (Collector, error) {
	return &windows.HostCollector{}, nil
}

func NewProcessCollector() (Collector, error) {
	return &windows.ProcessCollector{}, nil
}

func NewNetworkCollector() (Collector, error) {
	return &windows.NetworkCollector{}, nil
}

func NewPersistenceCollector() (Collector, error) {
	return &windows.PersistenceCollector{}, nil
}

func NewLoginCollector() (Collector, error) {
	return &windows.LoginCollector{}, nil
}

func NewFileCollector() (Collector, error) {
	return &windows.FileCollector{}, nil
}

func NewProcessEventCollector() (Collector, error) {
	return &windows.ProcessEventCollector{}, nil
}

func NewPowerShellEventCollector() (
	Collector,
	error,
) {

	return &windows.PowerShellEventCollector{},
		nil
}

func NewCapabilityCollector() (
	Collector,
	error,
) {

	return &windows.CapabilityCollector{},
		nil
}

func NewSecurityProviderCollector() (
	Collector,
	error,
) {

	return &windows.SecurityProviderCollector{},
		nil
}

func NewGenericEventCollector() (
	Collector,
	error,
) {

	return &windows.GenericEventCollector{},
		nil
}
