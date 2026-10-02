package analyzer

import (
	"strings"

	"ir-toolkit/internal/model"
)

func analyzePowerShellBlock(
	block model.PowerShellScriptBlock,
) *model.PowerShellFinding {

	text :=
		strings.ToLower(
			block.ScriptText,
		)

	if strings.TrimSpace(text) == "" {
		return nil
	}

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	indicators :=
		make(
			[]string,
			0,
		)

	// ----------------------------------------
	// Dynamic execution
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"invoke-expression",
			"iex ",
			"iex(",
		},
	) {

		score += 25

		reasons =
			append(
				reasons,
				"script uses dynamic expression execution",
			)

		indicators =
			append(
				indicators,
				"dynamic_execution",
			)
	}

	// ----------------------------------------
	// Download behavior
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"invoke-webrequest",
			"invoke-restmethod",
			"downloadstring",
			"downloadfile",
			"system.net.webclient",
			"http://",
			"https://",
		},
	) {

		score += 25

		reasons =
			append(
				reasons,
				"script contains network or download behavior",
			)

		indicators =
			append(
				indicators,
				"network_download",
			)
	}

	// ----------------------------------------
	// Encoded / transformation
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"frombase64string",
			"tobase64string",
			"base64",
		},
	) {

		score += 20

		reasons =
			append(
				reasons,
				"script uses Base64 encoding or decoding",
			)

		indicators =
			append(
				indicators,
				"base64",
			)
	}

	// ----------------------------------------
	// Reflection / assembly loading
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"[reflection.assembly]::load",
			"assembly]::load",
			"loadfile(",
			"loadfrom(",
		},
	) {

		score += 30

		reasons =
			append(
				reasons,
				"script performs in-memory or reflection-based assembly loading",
			)

		indicators =
			append(
				indicators,
				"assembly_loading",
			)
	}

	// ----------------------------------------
	// AMSI/security manipulation hints
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"amsiutils",
			"amsiinitfailed",
			"amsiscanbuffer",
			"scriptblocklogging",
			"etwprovider",
		},
	) {

		score += 40

		reasons =
			append(
				reasons,
				"script references PowerShell or Windows security instrumentation internals",
			)

		indicators =
			append(
				indicators,
				"security_instrumentation_reference",
			)
	}

	// ----------------------------------------
	// Credential-related hints
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"sekurlsa",
			"lsass",
			"credential",
			"getcredential",
			"securestring",
		},
	) {

		score += 20

		reasons =
			append(
				reasons,
				"script contains credential-related terms",
			)

		indicators =
			append(
				indicators,
				"credential_related",
			)
	}

	// ----------------------------------------
	// Process execution
	// ----------------------------------------

	if containsPowerShellAny(
		text,
		[]string{
			"start-process",
			"new-object diagnostics.process",
			"cmd.exe",
			"rundll32.exe",
			"regsvr32.exe",
			"mshta.exe",
			"certutil.exe",
		},
	) {

		score += 15

		reasons =
			append(
				reasons,
				"script launches or references native process execution",
			)

		indicators =
			append(
				indicators,
				"process_execution",
			)
	}

	if !block.Complete {

		reasons =
			append(
				reasons,
				"script block is incomplete because one or more fragments are missing",
			)
	}

	if block.
		RelatedHistoricalProcessID != "" {

		reasons =
			append(
				reasons,
				"script block is correlated with a historical PowerShell process",
			)
	}

	if score < 30 {
		return nil
	}

	finding :=
		&model.PowerShellFinding{
			ID: "PS-" +
				sanitizeFindingID(
					block.ScriptBlockID+
						"-"+
						block.ScriptSHA256,
				),

			Type: "powershell_script",

			Title: "High-interest PowerShell script block",

			Timestamp: block.Timestamp,

			ProcessID: block.ProcessID,

			ScriptBlockID: block.ScriptBlockID,

			ScriptSHA256: block.ScriptSHA256,

			ProcessName: block.RelatedProcessName,

			CommandLine: block.RelatedCommandLine,

			User: block.User,

			LogonID: block.LogonID,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),

			Indicators: uniqueStrings(
				indicators,
			),

			Preview: powerShellPreview(
				block.ScriptText,
				512,
			),
		}

	finding.Severity =
		powerShellSeverity(
			score,
		)

	return finding
}

func containsPowerShellAny(
	text string,
	patterns []string,
) bool {

	for _, pattern := range patterns {

		if strings.Contains(
			text,
			pattern,
		) {

			return true
		}
	}

	return false
}

func powerShellPreview(
	value string,
	maxLength int,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	if len(value) <= maxLength {
		return value
	}

	return value[:maxLength] +
		"..."
}

func powerShellSeverity(
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
