//go:build windows

package windows

func builtInWindowsEventDefinitions() []WindowsEventDefinition {

	return []WindowsEventDefinition{
		{
			ID: "task_scheduler",

			Channel: "Microsoft-Windows-TaskScheduler/Operational",

			EventIDs: []uint32{
				106,
				140,
				141,
				200,
				201,
			},

			MaxEvents: 5000,

			Enabled: true,
		},

		{
			ID: "wmi_activity",

			Channel: "Microsoft-Windows-WMI-Activity/Operational",

			EventIDs: []uint32{
				5857,
				5858,
				5860,
				5861,
			},

			MaxEvents: 5000,

			Enabled: true,
		},

		{
			ID: "terminal_services",

			Channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",

			EventIDs: []uint32{
				21,
				22,
				23,
				24,
				25,
			},

			MaxEvents: 5000,

			Enabled: true,
		},
	}
}
