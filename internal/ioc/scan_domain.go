package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func scanDomainIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	evidence CaseEvidence,
) {

	for _, rule := range rules {

		domain :=
			normalizeDomain(
				rule.Value,
			)

		if domain == "" {
			continue
		}

		for _, process := range evidence.Processes {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if !matchString(
				process.CommandLine,
				domain,
				"contains",
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "domain",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: "contains",

						Source: "process",

						Object: process.CommandLine,

						PID: process.PID,

						Process: process.Name,

						CommandLine: process.CommandLine,
					},
				)

			result.Statistics.
				DomainMatches++
		}
	}
}
