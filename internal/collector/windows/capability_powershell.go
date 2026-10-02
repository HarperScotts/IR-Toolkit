//go:build windows

package windows

import (
	"golang.org/x/sys/windows/registry"

	"ir-toolkit/internal/model"
)

func checkPowerShellScriptBlockLogging() model.CapabilityStatus {

	const keyPath = `SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

	key, err :=
		registry.OpenKey(
			registry.LOCAL_MACHINE,
			keyPath,
			registry.QUERY_VALUE,
		)

	if err != nil {

		return model.CapabilityStatus{
			Available: true,

			Enabled: false,

			Status: "disabled",

			Reason: "ScriptBlockLogging policy key not found",
		}
	}

	defer key.Close()

	value, _, err :=
		key.GetIntegerValue(
			"EnableScriptBlockLogging",
		)

	if err != nil ||
		value == 0 {

		return model.CapabilityStatus{
			Available: true,

			Enabled: false,

			Status: "disabled",
		}
	}

	return model.CapabilityStatus{
		Available: true,

		Enabled: true,

		Status: "enabled",
	}
}
