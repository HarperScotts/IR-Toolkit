package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func scanIPIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	network model.NetworkSnapshot,
) {

	for _, rule := range rules {

		expected :=
			normalizeIP(
				rule.Value,
			)

		for _, connection := range network.Connections {

			select {
			case <-ctx.Done():
				return
			default:
			}

			actual :=
				normalizeIP(
					connection.RemoteAddress,
				)

			if actual == "" ||
				actual != expected {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "ip",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: "exact",

						Source: "network",

						Object: connection.RemoteAddress,

						PID: connection.PID,

						Process: connection.ProcessName,

						Path: connection.ProcessPath,

						RemoteAddress: connection.RemoteAddress,

						RemotePort: connection.RemotePort,
					},
				)

			result.Statistics.
				IPMatches++
		}
	}
}
