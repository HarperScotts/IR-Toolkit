package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func analyzeExplicitCredentials(
	event model.LoginEvent,
) *model.LoginFinding {

	// 4648 很常见。
	// 单独出现不报警。

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	process :=
		strings.ToLower(
			event.ProcessName,
		)

	if strings.HasSuffix(
		process,
		`\cmd.exe`,
	) ||
		strings.HasSuffix(
			process,
			`\powershell.exe`,
		) ||
		strings.HasSuffix(
			process,
			`\pwsh.exe`,
		) {

		score += 30

		reasons =
			append(
				reasons,
				"explicit credentials were used by a command shell or PowerShell",
			)
	}

	if event.SourceIP != "" {

		score += 10

		reasons =
			append(
				reasons,
				"explicit credential event contains a remote source",
			)
	}

	if score < 30 {
		return nil
	}

	finding :=
		&model.LoginFinding{

			ID: fmt.Sprintf(
				"LOGIN-4648-%d",
				event.Timestamp.
					UnixNano(),
			),

			Type: "explicit_credentials",

			Title: "Explicit credentials used by command-line process",

			Timestamp: event.Timestamp,

			User: event.User,

			Domain: event.Domain,

			SourceIP: event.SourceIP,

			ProcessName: event.ProcessName,

			LogonID: normalizeLogonID(
				event.TargetLogonID,
			),

			Score: score,

			Reasons: reasons,

			RelatedEvents: []uint32{
				4648,
			},
		}

	finding.Severity =
		loginSeverity(
			score,
		)

	return finding
}
