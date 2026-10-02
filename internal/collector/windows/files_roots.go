//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strings"
)

func buildWindowsTriageRoots() []string {

	roots :=
		make(
			[]string,
			0,
			8,
		)

	add := func(
		value string,
	) {

		value =
			strings.TrimSpace(
				value,
			)

		if value == "" {
			return
		}

		value =
			filepath.Clean(
				value,
			)

		for _, existing := range roots {

			if strings.EqualFold(
				existing,
				value,
			) {
				return
			}
		}

		roots =
			append(
				roots,
				value,
			)
	}

	systemRoot :=
		os.Getenv(
			"SystemRoot",
		)

	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}

	add(
		filepath.Join(
			systemRoot,
			"Temp",
		),
	)

	add(
		os.Getenv(
			"TEMP",
		),
	)

	add(
		os.Getenv(
			"TMP",
		),
	)

	appData :=
		os.Getenv(
			"APPDATA",
		)

	add(appData)

	localAppData :=
		os.Getenv(
			"LOCALAPPDATA",
		)

	add(localAppData)

	public :=
		os.Getenv(
			"PUBLIC",
		)

	if public == "" {
		public = `C:\Users\Public`
	}

	add(public)

	userProfile :=
		os.Getenv(
			"USERPROFILE",
		)

	if userProfile != "" {

		add(
			filepath.Join(
				userProfile,
				"Downloads",
			),
		)

		add(
			filepath.Join(
				userProfile,
				"Desktop",
			),
		)
	}

	return roots
}
