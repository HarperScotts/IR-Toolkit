//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"ir-toolkit/internal/model"
)

func collectWindowsServices(
	ctx context.Context,
) ([]model.ServiceInfo, []string) {

	result := make(
		[]model.ServiceInfo,
		0,
	)

	warnings := make(
		[]string,
		0,
	)

	manager, err := mgr.Connect()

	if err != nil {

		return result,
			[]string{
				fmt.Sprintf(
					"connect service manager: %v",
					err,
				),
			}
	}

	defer manager.Disconnect()

	names, err :=
		manager.ListServices()

	if err != nil {

		return result,
			[]string{
				fmt.Sprintf(
					"list services: %v",
					err,
				),
			}
	}

	sort.Strings(names)

	for _, name := range names {

		select {

		case <-ctx.Done():
			return result,
				append(
					warnings,
					ctx.Err().Error(),
				)

		default:
		}

		item := model.ServiceInfo{
			Name: name,
		}

		service, err :=
			manager.OpenService(
				name,
			)

		if err != nil {

			item.Errors =
				append(
					item.Errors,
					fmt.Sprintf(
						"open service: %v",
						err,
					),
				)

			result =
				append(
					result,
					item,
				)

			continue
		}

		// -------------------------------
		// Configuration
		// -------------------------------

		config, err :=
			service.Config()

		if err != nil {

			item.Errors =
				append(
					item.Errors,
					fmt.Sprintf(
						"query config: %v",
						err,
					),
				)

		} else {

			item.DisplayName =
				config.DisplayName

			item.Description =
				config.Description

			item.BinaryPath =
				config.BinaryPathName

			item.Account =
				config.ServiceStartName

			item.ServiceType =
				config.ServiceType

			item.StartType =
				serviceStartTypeName(
					config.StartType,
				)

			item.DelayedAutoStart =
				config.DelayedAutoStart
		}

		// -------------------------------
		// Runtime Status
		// -------------------------------

		status, err :=
			service.Query()

		if err != nil {

			item.Errors =
				append(
					item.Errors,
					fmt.Sprintf(
						"query status: %v",
						err,
					),
				)

		} else {

			item.State =
				serviceStateName(
					status.State,
				)

			item.PID =
				status.ProcessId
		}

		service.Close()

		result =
			append(
				result,
				item,
			)
	}

	return result, warnings
}

func serviceStartTypeName(
	value uint32,
) string {

	switch value {

	case windows.SERVICE_BOOT_START:
		return "Boot"

	case windows.SERVICE_SYSTEM_START:
		return "System"

	case windows.SERVICE_AUTO_START:
		return "Automatic"

	case windows.SERVICE_DEMAND_START:
		return "Manual"

	case windows.SERVICE_DISABLED:
		return "Disabled"

	default:
		return fmt.Sprintf(
			"Unknown(%d)",
			value,
		)
	}
}

func serviceStateName(
	state svc.State,
) string {

	switch state {

	case svc.Stopped:
		return "Stopped"

	case svc.StartPending:
		return "StartPending"

	case svc.StopPending:
		return "StopPending"

	case svc.Running:
		return "Running"

	case svc.ContinuePending:
		return "ContinuePending"

	case svc.PausePending:
		return "PausePending"

	case svc.Paused:
		return "Paused"

	default:
		return fmt.Sprintf(
			"Unknown(%d)",
			state,
		)
	}
}
