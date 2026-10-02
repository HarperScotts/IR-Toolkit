//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"

	"ir-toolkit/internal/model"
)

func checkSysmonCapability() model.CapabilityStatus {

	channel :=
		checkEventChannel(
			"Microsoft-Windows-Sysmon/Operational",
		)

	if channel.Available {

		channel.Status =
			"installed"

		return channel
	}

	/*
		再通过 Service 注册项辅助判断。
	*/

	key, err :=
		registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Sysmon64`,
			registry.QUERY_VALUE,
		)

	if err == nil {

		key.Close()

		return model.CapabilityStatus{
			Available: true,

			Enabled: true,

			Status: "installed",
		}
	}

	key, err =
		registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SYSTEM\CurrentControlSet\Services\Sysmon`,
			registry.QUERY_VALUE,
		)

	if err == nil {

		key.Close()

		return model.CapabilityStatus{
			Available: true,

			Enabled: true,

			Status: "installed",
		}
	}

	return model.CapabilityStatus{
		Available: false,

		Enabled: false,

		Status: "not_installed",
	}
}
