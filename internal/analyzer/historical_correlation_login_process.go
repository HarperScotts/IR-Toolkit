package analyzer

import (
	"context"

	"ir-toolkit/internal/model"
)

func buildLoginProcessCorrelationEdges(
	ctx context.Context,
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	login model.LoginAnalysis,
	history model.ProcessHistoryAnalysis,
) {

	loginIDs :=
		make(
			map[string]struct{},
		)

	for _, session := range login.Sessions {

		id :=
			normalizeLogonID(
				session.LogonID,
			)

		if id != "" {
			loginIDs[id] =
				struct{}{}
		}
	}

	for _, process := range history.Processes {

		select {
		case <-ctx.Done():
			return
		default:
		}

		logonID :=
			normalizeLogonID(
				process.LogonID,
			)

		if logonID == "" {
			continue
		}

		if _, exists :=
			loginIDs[logonID]; !exists {

			continue
		}

		addCorrelationEdge(
			result,
			seen,
			model.CorrelationEdge{
				From: correlationLoginNodeID(
					logonID,
				),

				To: process.ID,

				Type: "logon_process",

				Confidence: "high",

				Score: 100,

				Basis: []model.CorrelationEvidence{
					{
						Type: "logon_id",

						Value: logonID,

						Description: "4688 SubjectLogonId matches the login session LogonId",
					},
				},

				Timestamp: process.Timestamp,
			},
		)
	}
}
