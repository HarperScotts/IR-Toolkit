package analyzer

import (
	"context"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

const rdpLoginCorrelationWindow = 2 * time.Minute

func buildRDPSessionCorrelationEdges(
	ctx context.Context,
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	login model.LoginAnalysis,
	windowsEvents model.WindowsEventAnalysis,
) {

	for _, activity := range windowsEvents.Activities {

		if activity.Type !=
			"RDP_SESSION_LOGON" {

			continue
		}

		for _, session := range login.Sessions {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if session.LogonType != 10 {
				continue
			}

			score := 0

			basis :=
				make(
					[]model.CorrelationEvidence,
					0,
				)

			leftUser :=
				normalizeCorrelationUser(
					activity.User,
				)

			rightUser :=
				normalizeCorrelationUser(
					formatDomainUser(
						session.Domain,
						session.User,
					),
				)

			if leftUser != "" &&
				rightUser != "" &&
				(leftUser ==
					rightUser ||
					strings.HasSuffix(leftUser, `\`+normalizeCorrelationUser(session.User))) {

				score += 30

				basis =
					append(
						basis,
						model.CorrelationEvidence{
							Type: "user",

							Value: activity.User,

							Description: "Terminal Services and 4624 identify the same user",
						},
					)
			}

			if activity.SourceIP != "" &&
				session.SourceIP != "" &&
				strings.EqualFold(
					activity.SourceIP,
					session.SourceIP,
				) {

				score += 35

				basis =
					append(
						basis,
						model.CorrelationEvidence{
							Type: "source_ip",

							Value: activity.SourceIP,

							Description: "Terminal Services and 4624 identify the same source address",
						},
					)
			}

			if withinTimeWindow(
				activity.Timestamp,
				session.Timestamp,
				rdpLoginCorrelationWindow,
			) {

				score += 25

				basis =
					append(
						basis,
						model.CorrelationEvidence{
							Type: "time",

							Description: "events occurred within two minutes",
						},
					)
			}

			/*
				不要仅凭时间建立边。

				至少要求 user/source IP 其中一个也匹配。
			*/
			if score < 55 {
				continue
			}

			addCorrelationEdge(
				result,
				seen,
				model.CorrelationEdge{
					From: activity.ID,

					To: correlationLoginNodeID(
						session.LogonID,
					),

					Type: "rdp_login",

					Confidence: correlationConfidence(
						score,
					),

					Score: score,

					Basis: basis,

					Timestamp: session.Timestamp,
				},
			)
		}
	}
}
