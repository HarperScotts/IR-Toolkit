package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func analyzeLoginSession(
	session *model.LoginSessionAnalysis,
) []model.LoginFinding {

	result :=
		make(
			[]model.LoginFinding,
			0,
		)

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	// --------------------------------------------------
	// RDP
	// --------------------------------------------------

	if session.LogonType == 10 {

		score += 30

		reasons =
			append(
				reasons,
				"remote interactive logon (RDP)",
			)
	}

	// --------------------------------------------------
	// Remote source
	// --------------------------------------------------

	if session.SourceIP != "" &&
		isExternalLoginSource(
			session.SourceIP,
		) {

		score += 20

		reasons =
			append(
				reasons,
				"logon originated from a non-local address",
			)
	}

	// --------------------------------------------------
	// Privileged session
	// --------------------------------------------------

	if session.Privileged {

		score += 20

		reasons =
			append(
				reasons,
				"session received special privileges",
			)
	}

	// --------------------------------------------------
	// session.Process's
	// --------------------------------------------------

	if session.ProcessCount > 0 {

		reasons =
			append(
				reasons,
				fmt.Sprintf(
					"%d processes are associated with this logon session",
					session.ProcessCount,
				),
			)
	}

	// --------------------------------------------------
	// session network connections
	// --------------------------------------------------

	if session.
		ProcessesWithExternalNetwork > 0 {

		score += 30

		reasons =
			append(
				reasons,
				fmt.Sprintf(
					"%d process(es) in this logon session have external network connections",
					session.
						ProcessesWithExternalNetwork,
				),
			)
	}
	// --------------------------------------------------
	// Is there a shell in the session?
	// --------------------------------------------------
	shellPIDs :=
		make(
			[]uint32,
			0,
		)

	for _, process := range session.Processes {

		if isShellProcessName(
			process.Name,
		) {

			shellPIDs =
				append(
					shellPIDs,
					process.PID,
				)
		}
	}

	if len(shellPIDs) > 0 &&
		session.SourceIP != "" {

		score += 20

		reasons =
			append(
				reasons,
				"remote logon session spawned a command shell",
			)
	}
	// --------------------------------------------------
	// Remote + Privileges + Shell + External
	// --------------------------------------------------
	if session.SourceIP != "" &&
		session.Privileged &&
		len(shellPIDs) > 0 &&
		session.
			ProcessesWithExternalNetwork > 0 {

		score += 30

		reasons =
			append(
				reasons,
				"remote privileged session spawned a shell and contains external network activity",
			)
	}
	// --------------------------------------------------
	// High-interest usernames
	// --------------------------------------------------

	if isAdministrativeUser(
		session.User,
	) {

		score += 15

		reasons =
			append(
				reasons,
				"administrative account was used",
			)
	}

	/*
		重要：

		正常的 SYSTEM / LOCAL SERVICE /
		NETWORK SERVICE 不因为 4672 自动报警。
	*/

	if isBuiltInServiceAccount(
		session.User,
		session.Domain,
	) {

		return result
	}

	if score < 30 {
		return result
	}

	/*
		relatedPIDs

	*/
	relatedPIDs :=
		make(
			[]uint32,
			0,
			len(session.Processes),
		)

	for _, process := range session.Processes {

		relatedPIDs =
			append(
				relatedPIDs,
				process.PID,
			)
	}

	finding :=
		model.LoginFinding{

			ID: fmt.Sprintf(
				"LOGIN-SESSION-%s",
				sanitizeFindingID(
					session.LogonID,
				),
			),

			Type: "login_session",

			Title: "Remote or privileged logon session",

			Timestamp: session.Timestamp,

			User: session.User,

			Domain: session.Domain,

			SourceIP: session.SourceIP,

			LogonType: session.LogonType,

			LogonTypeName: session.LogonTypeName,

			LogonID: session.LogonID,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),

			RelatedEvents: session.Events,

			RelatedPIDs: relatedPIDs,
		}

	finding.Severity =
		loginSeverity(
			score,
		)

	result =
		append(
			result,
			finding,
		)

	return result
}

func isBuiltInServiceAccount(
	user string,
	domain string,
) bool {

	u :=
		strings.ToLower(
			strings.TrimSpace(
				user,
			),
		)

	d :=
		strings.ToLower(
			strings.TrimSpace(
				domain,
			),
		)

	switch u {

	case "system",
		"local service",
		"network service",
		"localservice",
		"networkservice":

		return true
	}

	if d == "nt authority" {

		switch u {

		case "system",
			"local service",
			"network service":

			return true
		}
	}

	return false
}

func isAdministrativeUser(
	user string,
) bool {

	value :=
		strings.ToLower(
			strings.TrimSpace(
				user,
			),
		)

	switch value {

	case "administrator",
		"admin",
		"root":

		return true
	}

	return false
}

func loginSeverity(
	score int,
) string {

	switch {

	case score >= 80:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}

func isExternalLoginSource(
	value string,
) bool {

	value =
		strings.TrimSpace(
			value,
		)

	switch value {

	case "",
		"-",
		"127.0.0.1",
		"::1":

		return false
	}

	return true
}
