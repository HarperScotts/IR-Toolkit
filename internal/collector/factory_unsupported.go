//go:build !linux && !windows

package collector

import "ir-toolkit/internal/collector/linux"

func NewHostCollector() (Collector, error) {
	return &UnsupportedCollector{
		name: "host",
	}, nil
}

func NewProcessCollector() (Collector, error) {
	return &UnsupportedCollector{
		name: "process",
	}, nil
}

func NewNetworkCollector() (Collector, error) {
	return &UnsupportedCollector{
		name: "mac_network",
	}, nil
}

func NewPersistenceCollector() (Collector, error) {
	return &UnsupportedCollector{
		name: "mac_Persistence",
	}, nil
}

func NewLoginCollector() (Collector, error) {
	return newUnsupportedCollector(
		"login",
	), nil
}

func NewFileCollector() (Collector, error) {
	return newUnsupportedCollector(
		"files",
	), nil
}

func NewProcessEventCollector() (
	Collector,
	error,
) {

	return newUnsupportedCollector(
		"process_events",
	), nil
}

func NewPowerShellEventCollector() (
	Collector,
	error,
) {

	return newUnsupportedCollector(
		"powershell_events",
	), nil
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
