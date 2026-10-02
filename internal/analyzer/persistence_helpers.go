package analyzer

import (
	"strings"

	"ir-toolkit/internal/model"
)

func isUserWritableOrTransientPath(
	path string,
) bool {

	value :=
		normalizeExecutablePath(
			path,
		)

	if value == "" {
		return false
	}

	patterns := []string{
		`\windows\temp\`,
		`\users\public\`,
		`\appdata\local\temp\`,
		`\appdata\roaming\`,
		`\downloads\`,
		`\desktop\`,

		`%temp%\`,
		`%tmp%\`,
		`%appdata%\`,
		`%localappdata%\`,
		`%userprofile%\downloads\`,
		`%userprofile%\desktop\`,
	}

	for _, pattern := range patterns {

		if strings.Contains(
			value,
			pattern,
		) {

			return true
		}
	}

	return false
}

func isSuspiciousPersistenceExecutable(
	path string,
) bool {

	value :=
		normalizeExecutablePath(
			path,
		)

	name := value

	if index :=
		strings.LastIndex(
			value,
			`\`,
		); index >= 0 {

		name =
			value[index+1:]
	}

	switch name {

	case "powershell.exe",
		"pwsh.exe",

		"cmd.exe",

		"wscript.exe",
		"cscript.exe",

		"mshta.exe",

		"rundll32.exe",
		"regsvr32.exe",

		"certutil.exe",
		"bitsadmin.exe",

		"curl.exe",
		"wget.exe":

		return true
	}

	return false
}

func hasSuspiciousPersistenceCommand(
	command string,
) bool {

	value :=
		strings.ToLower(
			command,
		)

	keywords := []string{
		"-encodedcommand",
		"-encodedarguments",
		"frombase64string",
		"downloadstring",
		"downloadfile",
		"invoke-webrequest",
		"invoke-restmethod",
		"javascript:",
		"vbscript:",
	}

	for _, keyword := range keywords {

		if strings.Contains(
			value,
			keyword,
		) {

			return true
		}
	}

	return containsCommandToken(
		value,
		"-enc",
	)
}

func persistenceSeverity(
	score int,
) string {

	switch {

	case score >= 90:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}

func processByPID(
	processes map[uint32]model.ProcessNetworkAnalysis,
	pid uint32,
) (
	model.ProcessNetworkAnalysis,
	bool,
) {

	process, exists :=
		processes[pid]

	return process, exists
}

func isSystemAccount(
	account string,
) bool {

	value :=
		strings.ToLower(
			strings.TrimSpace(
				account,
			),
		)

	switch value {

	case "localsystem",
		"system",
		"nt authority\\system":

		return true
	}

	return false
}

func hasPersistenceTrigger(
	triggers []string,
) bool {

	for _, trigger := range triggers {

		switch strings.ToLower(
			trigger,
		) {

		case "boottrigger",
			"logontrigger",
			"registrationtrigger":

			return true
		}
	}

	return false
}

func sanitizeFindingID(
	value string,
) string {

	value =
		strings.ToUpper(
			value,
		)

	var builder strings.Builder

	for _, r := range value {

		switch {

		case r >= 'A' &&
			r <= 'Z':

			builder.WriteRune(r)

		case r >= '0' &&
			r <= '9':

			builder.WriteRune(r)

		default:

			builder.WriteByte(
				'-',
			)
		}
	}

	result :=
		strings.Trim(
			builder.String(),
			"-",
		)

	for strings.Contains(
		result,
		"--",
	) {

		result =
			strings.ReplaceAll(
				result,
				"--",
				"-",
			)
	}

	return result
}
