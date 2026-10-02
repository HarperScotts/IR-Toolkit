//go:build windows

package windows

import (
	"strings"

	"golang.org/x/sys/windows/svc/mgr"

	"ir-toolkit/internal/model"
)

func discoverSecurityServices(
	result *model.SecurityProviderSnapshot,
) {

	manager, err :=
		mgr.Connect()

	if err != nil {

		result.Warnings =
			append(
				result.Warnings,
				"open service manager for security provider discovery: "+
					err.Error(),
			)

		return
	}

	defer manager.Disconnect()

	names, err :=
		manager.ListServices()

	if err != nil {

		result.Warnings =
			append(
				result.Warnings,
				"list services for security provider discovery: "+
					err.Error(),
			)

		return
	}

	for _, name := range names {

		service, err :=
			manager.OpenService(
				name,
			)

		if err != nil {
			continue
		}

		config, err :=
			service.Config()

		if err != nil {

			service.Close()

			continue
		}

		status, statusErr :=
			service.Query()

		service.Close()

		if !looksLikeSecurityService(
			name,
			config.DisplayName,
			config.BinaryPathName,
			result.Providers,
		) {

			continue
		}

		state := ""

		if statusErr == nil {
			state =
				serviceStateName(
					status.State,
				)
		}

		entry :=
			model.SecurityProviderService{
				Name: name,

				DisplayName: config.DisplayName,

				State: state,

				ImagePath: config.BinaryPathName,
			}

		attachSecurityService(
			result,
			entry,
		)
	}
}

func looksLikeSecurityService(
	name string,
	displayName string,
	path string,
	providers []model.SecurityProvider,
) bool {

	combined :=
		strings.ToLower(
			name +
				" " +
				displayName +
				" " +
				path,
		)

	systemPatterns :=
		[]string{
			"windefend",
			"securityhealthservice",
			"sense",
			"sysmon",
			"sysmon64",
		}

	for _, pattern := range systemPatterns {

		if strings.Contains(
			combined,
			pattern,
		) {

			return true
		}
	}

	for _, provider := range providers {

		product :=
			strings.ToLower(
				provider.Name,
			)

		if product != "" &&
			strings.Contains(
				combined,
				product,
			) {

			return true
		}

		executable :=
			normalizeSecurityExecutable(
				provider.ProductExecutable,
			)

		if executable != "" &&
			strings.Contains(
				normalizeSecurityExecutable(
					path,
				),
				executable,
			) {

			return true
		}
	}

	return false
}

func normalizeSecurityExecutable(
	value string,
) string {

	value =
		strings.ToLower(
			strings.TrimSpace(
				value,
			),
		)

	value =
		strings.Trim(
			value,
			`"'`,
		)

	return value
}

func attachSecurityService(
	result *model.SecurityProviderSnapshot,
	service model.SecurityProviderService,
) {

	lower :=
		strings.ToLower(
			service.Name +
				" " +
				service.DisplayName +
				" " +
				service.ImagePath,
		)

	for index := range result.Providers {

		provider :=
			&result.Providers[index]

		name :=
			strings.ToLower(
				provider.Name,
			)

		executable :=
			normalizeSecurityExecutable(
				provider.ProductExecutable,
			)

		if name != "" &&
			strings.Contains(
				lower,
				name,
			) {

			provider.Services =
				append(
					provider.Services,
					service,
				)

			return
		}

		if executable != "" &&
			strings.Contains(
				normalizeSecurityExecutable(
					service.ImagePath,
				),
				executable,
			) {

			provider.Services =
				append(
					provider.Services,
					service,
				)

			return
		}
	}

	/*
		找不到 SecurityCenter Provider，
		仍然保留这个安全服务。
	*/

	result.Providers =
		append(
			result.Providers,

			model.SecurityProvider{
				ID: "service-" +
					strings.ToLower(
						service.Name,
					),

				Name: service.DisplayName,

				Type: "security_service",

				Registered: false,

				Source: "windows_service",

				Services: []model.SecurityProviderService{
					service,
				},
			},
		)
}
