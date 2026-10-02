package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func scanHashIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	files model.FileTriageSnapshot,
) {

	for _, rule := range rules {

		expected :=
			normalizeHash(
				rule.Value,
			)

		if expected == "" {
			continue
		}

		for _, file := range files.Files {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if normalizeHash(
				file.SHA256,
			) != expected {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "hash",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: "exact",

						Source: "files",

						Object: file.Path,

						Path: file.Path,

						SHA256: file.SHA256,
					},
				)

			result.Statistics.
				HashMatches++
		}
	}
}
