//go:build linux

package collector

import "ir-toolkit/internal/collector/linux"

func NewHostCollector() (Collector, error) {
	return &linux.HostCollector{}, nil
}

func NewProcessCollector() (Collector, error) {
	return &linux.ProcessCollector{}, nil
}

func NewNetworkCollector() (Collector, error) {
	return newUnsupportedCollector(
		"linux_network",
	), nil
}

func NewPersistenceCollector() (Collector, error) {
	return &linux.PersistenceCollector{}, nil
}

func NewLoginCollector() (Collector, error) {
	return &linux.LoginCollector{}, nil
}

func NewFileCollector() (Collector, error) {
	return &linux.FileCollector{}, nil
}

func NewProcessEventCollector() (
	Collector,
	error,
) {

	return &linux.ProcessEventCollector{},
		nil
}

func NewPowerShellEventCollector() (
	Collector,
	error,
) {

	return &linux.PowerShellEventCollector{},
		nil
}

func NewCapabilityCollector() (
	Collector,
	error,
) {

	return &linux.CapabilityCollector{},
		nil
}

func NewSecurityProviderCollector() (
	Collector,
	error,
) {

	return &linux.SecurityProviderCollector{},
		nil
}

func NewGenericEventCollector() (
	Collector,
	error,
) {

	return newUnsupportedCollector(
		"generic_events",
	), nil
}
