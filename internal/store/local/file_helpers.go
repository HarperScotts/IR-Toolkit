package local

import (
	"strconv"
	"strings"

	"ir-toolkit/internal/model"
)

func normalizeFileEvidencePath(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}

func fileEvidenceMatchesQuery(
	file model.FileTriageItem,
	query string,
) bool {

	if query == "" {
		return true
	}

	values :=
		[]string{
			file.Path,
			file.Name,
			file.Extension,
			file.Owner,
			file.SHA256,
			file.ZoneIdentifier,
			file.Source,

			strconv.FormatInt(
				file.Size,
				10,
			),

			strconv.FormatBool(
				file.Executable,
			),
		}

	for _, stream := range file.ADS {

		values =
			append(
				values,
				stream.Name,

				strconv.FormatInt(
					stream.Size,
					10,
				),
			)
	}

	return searchContains(
		query,
		values...,
	)
}
