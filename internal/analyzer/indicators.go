package analyzer

import (
	"strings"

	"ir-toolkit/internal/model"
)

func generateIndicators(
	process *model.ProcessNetworkAnalysis,
) []string {

	indicators := make(
		[]string,
		0,
	)

	name := strings.ToLower(
		strings.TrimSpace(
			process.ProcessName,
		),
	)

	commandLine := strings.ToLower(
		process.CommandLine,
	)

	hasExternalNetwork :=
		len(process.ExternalConnections) > 0

	// --------------------------------------------------
	// Shell / Script Engine + External Network
	// --------------------------------------------------

	if hasExternalNetwork {

		switch name {

		case "powershell.exe":
			indicators = append(
				indicators,
				"powershell_external_network",
			)

		case "pwsh.exe":
			indicators = append(
				indicators,
				"pwsh_external_network",
			)

		case "cmd.exe":
			indicators = append(
				indicators,
				"cmd_external_network",
			)

		case "wscript.exe":
			indicators = append(
				indicators,
				"wscript_external_network",
			)

		case "cscript.exe":
			indicators = append(
				indicators,
				"cscript_external_network",
			)

		case "mshta.exe":
			indicators = append(
				indicators,
				"mshta_external_network",
			)

		case "rundll32.exe":
			indicators = append(
				indicators,
				"rundll32_external_network",
			)

		case "regsvr32.exe":
			indicators = append(
				indicators,
				"regsvr32_external_network",
			)
		}
	}

	// --------------------------------------------------
	// Download / Transfer Utilities + External Network
	// --------------------------------------------------

	if hasExternalNetwork {

		switch name {

		case "certutil.exe":
			indicators = append(
				indicators,
				"certutil_external_network",
			)

		case "bitsadmin.exe":
			indicators = append(
				indicators,
				"bitsadmin_external_network",
			)

		case "curl.exe", "curl":
			indicators = append(
				indicators,
				"curl_external_network",
			)

		case "wget.exe", "wget":
			indicators = append(
				indicators,
				"wget_external_network",
			)
		}
	}

	// --------------------------------------------------
	// Suspicious PowerShell / Script Parameters
	// --------------------------------------------------

	if containsAny(
		commandLine,

		"-encodedcommand",
		"-encodedarguments",
		"frombase64string",
		"downloadstring",
		"downloadfile",
		"invoke-webrequest",
		"invoke-restmethod",
	) {

		indicators = append(
			indicators,
			"suspicious_script_commandline",
		)
	}

	// PowerShell 经常使用缩写 -enc。
	// 单独检查 token，避免普通字符串中偶然出现 "-enc"。
	if containsCommandToken(
		commandLine,
		"-enc",
	) {
		indicators = append(
			indicators,
			"powershell_encoded_command",
		)
	}

	return uniqueStrings(
		indicators,
	)
}

func containsAny(
	value string,
	keywords ...string,
) bool {

	for _, keyword := range keywords {

		if strings.Contains(
			value,
			strings.ToLower(keyword),
		) {
			return true
		}
	}

	return false
}

func containsCommandToken(
	commandLine string,
	token string,
) bool {

	fields := strings.Fields(
		commandLine,
	)

	for _, field := range fields {

		field = strings.Trim(
			field,
			`"'`,
		)

		if strings.EqualFold(
			field,
			token,
		) {
			return true
		}
	}

	return false
}

func uniqueStrings(
	values []string,
) []string {

	if len(values) < 2 {
		return values
	}

	seen := make(
		map[string]struct{},
		len(values),
	)

	result := make(
		[]string,
		0,
		len(values),
	)

	for _, value := range values {

		if _, exists := seen[value]; exists {
			continue
		}

		seen[value] = struct{}{}

		result = append(
			result,
			value,
		)
	}

	return result
}
