package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func scanProcessNameIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	processes []model.Process,
) {

	for _, rule := range rules {

		for _, process := range processes {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if !matchString(
				process.Name,
				rule.Value,
				rule.Match,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "process_name",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: normalizeMatchType(
							rule.Match,
						),

						Source: "process",

						Object: process.Name,

						PID: process.PID,

						Process: process.Name,

						Path: process.Path,

						CommandLine: process.CommandLine,
					},
				)

			result.Statistics.
				ProcessNameMatches++
		}
	}
}

func scanCommandLineIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	processes []model.Process,
) {

	for _, rule := range rules {

		matchType :=
			rule.Match

		if matchType == "" {
			matchType =
				"contains"
		}

		for _, process := range processes {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if !matchString(
				process.CommandLine,
				rule.Value,
				matchType,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "command_line",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: matchType,

						Source: "process",

						Object: process.CommandLine,

						PID: process.PID,

						Process: process.Name,

						Path: process.Path,

						CommandLine: process.CommandLine,
					},
				)

			result.Statistics.
				CommandLineMatches++
		}
	}
}
