package analyzer

import "strings"

func extractExecutable(
	command string,
) string {

	command = strings.TrimSpace(
		command,
	)

	if command == "" {
		return ""
	}

	// --------------------------------------------------
	// "C:\Program Files\xxx\app.exe" arguments
	// --------------------------------------------------

	if strings.HasPrefix(
		command,
		`"`,
	) {

		remaining :=
			command[1:]

		if index :=
			strings.Index(
				remaining,
				`"`,
			); index >= 0 {

			return strings.TrimSpace(
				remaining[:index],
			)
		}
	}

	// --------------------------------------------------
	// 'C:\xxx\app.exe' arguments
	// --------------------------------------------------

	if strings.HasPrefix(
		command,
		`'`,
	) {

		remaining :=
			command[1:]

		if index :=
			strings.Index(
				remaining,
				`'`,
			); index >= 0 {

			return strings.TrimSpace(
				remaining[:index],
			)
		}
	}

	lower :=
		strings.ToLower(
			command,
		)

	// 很多服务配置存在：
	//
	// C:\Program Files\Vendor\App.exe -service
	//
	// 即便路径没有引号，也尽量取到 .exe 为止。
	if index :=
		strings.Index(
			lower,
			".exe",
		); index >= 0 {

		return strings.TrimSpace(
			command[:index+4],
		)
	}

	// Linux / script / command fallback。
	fields :=
		strings.Fields(
			command,
		)

	if len(fields) == 0 {
		return ""
	}

	return strings.Trim(
		fields[0],
		`"'`,
	)
}

func normalizeExecutablePath(
	value string,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	value =
		strings.Trim(
			value,
			`"'`,
		)

	value =
		strings.ReplaceAll(
			value,
			"/",
			`\`,
		)

	return strings.ToLower(
		value,
	)
}
