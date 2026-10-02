//go:build windows

package windows

import "ir-toolkit/internal/model"

func discoverSecurityEventChannels(
	result *model.SecurityProviderSnapshot,
) {

	candidates :=
		[]model.SecurityEventChannel{
			{
				Name: "Security",

				Provider: "Windows",

				Category: "security",
			},

			{
				Name: "Microsoft-Windows-PowerShell/Operational",

				Provider: "PowerShell",

				Category: "powershell",
			},

			{
				Name: "Microsoft-Windows-Windows Defender/Operational",

				Provider: "Microsoft Defender",

				Category: "antivirus",
			},

			{
				Name: "Microsoft-Windows-Sysmon/Operational",

				Provider: "Sysmon",

				Category: "telemetry",
			},

			{
				Name: "Microsoft-Windows-TaskScheduler/Operational",

				Provider: "Task Scheduler",

				Category: "persistence",
			},

			{
				Name: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",

				Provider: "Windows Firewall",

				Category: "network",
			},

			{
				Name: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",

				Provider: "Terminal Services",

				Category: "remote_access",
			},

			{
				Name: "Microsoft-Windows-WMI-Activity/Operational",

				Provider: "WMI",

				Category: "execution",
			},

			{
				Name: "Microsoft-Windows-AppLocker/EXE and DLL",

				Provider: "AppLocker",

				Category: "application_control",
			},
		}

	for _, candidate := range candidates {

		status :=
			checkEventChannel(
				candidate.Name,
			)

		candidate.Available =
			status.Available

		candidate.Enabled =
			status.Enabled

		result.EventChannels =
			append(
				result.EventChannels,
				candidate,
			)

		if !candidate.Available {
			continue
		}

		attachEventChannelToProvider(
			result,
			candidate,
		)
	}
}

func attachEventChannelToProvider(
	result *model.SecurityProviderSnapshot,
	channel model.SecurityEventChannel,
) {

	for index := range result.Providers {

		provider :=
			&result.Providers[index]

		if provider.Name ==
			channel.Provider {

			provider.EventChannels =
				append(
					provider.EventChannels,
					channel.Name,
				)

			return
		}
	}
}

func buildSecurityProviderStatistics(
	result *model.SecurityProviderSnapshot,
) {

	result.Statistics.ProviderCount =
		uint32(
			len(result.Providers),
		)

	for _, provider := range result.Providers {

		switch provider.Type {

		case "antivirus":

			result.Statistics.
				AntivirusCount++

		case "antispyware":

			result.Statistics.
				AntispywareCount++

		case "firewall":

			result.Statistics.
				FirewallCount++

		case "security_service":

			result.Statistics.
				SecurityServiceCount++
		}
	}

	for _, channel := range result.EventChannels {

		if channel.Available {

			result.Statistics.
				EventChannelCount++
		}
	}
}
