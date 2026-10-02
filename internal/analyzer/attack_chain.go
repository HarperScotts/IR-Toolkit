package analyzer

import (
	"fmt"

	"ir-toolkit/internal/model"
)

func buildAttackChains(
	login model.LoginAnalysis,
	relationships model.ProcessRelationshipAnalysis,
	persistence model.PersistenceAnalysis,
) []model.AttackChain {

	result :=
		make(
			[]model.AttackChain,
			0,
		)

	processMap :=
		make(
			map[uint32]model.ProcessRelationship,
		)

	for _, process := range relationships.Processes {

		processMap[process.PID] =
			process
	}

	persistenceByPID :=
		make(
			map[uint32][]model.PersistenceFinding,
		)

	for _, finding := range persistence.Findings {

		if finding.RelatedPID == 0 {
			continue
		}

		persistenceByPID[finding.RelatedPID] =
			append(
				persistenceByPID[finding.RelatedPID],
				finding,
			)
	}

	for _, session := range login.Sessions {

		// 只关注远程来源。
		if session.SourceIP == "" {
			continue
		}

		for _, process := range session.Processes {

			_, exists :=
				processMap[process.PID]

			if !exists {
				continue
			}

			score := 20

			reasons :=
				[]string{
					"process belongs to a remote logon session",
				}

			nodeIDs :=
				[]string{
					"login:" +
						normalizeLogonID(
							session.LogonID,
						),

					fmt.Sprintf(
						"process:%d",
						process.PID,
					),
				}

			chainNames :=
				[]string{
					formatLoginLabel(
						session,
					),

					process.Name,
				}

			if session.Privileged {

				score += 20

				reasons =
					append(
						reasons,
						"remote logon session received special privileges",
					)
			}

			if isShellProcessName(
				process.Name,
			) {

				score += 20

				reasons =
					append(
						reasons,
						"remote session contains a command shell",
					)
			}

			if len(
				process.
					ExternalConnections,
			) > 0 {

				score += 30

				reasons =
					append(
						reasons,
						"session process has external network activity",
					)

				for _, connection := range process.
					ExternalConnections {

					nodeIDs =
						append(
							nodeIDs,
							networkNodeID(
								process.PID,
								connection,
							),
						)

					chainNames =
						append(
							chainNames,
							fmt.Sprintf(
								"%s:%d",
								connection.
									RemoteAddress,
								connection.
									RemotePort,
							),
						)
				}
			}

			if findings, exists :=
				persistenceByPID[process.PID]; exists {

				score += 30

				reasons =
					append(
						reasons,
						"process is associated with suspicious persistence evidence",
					)

				for _, finding := range findings {

					nodeIDs =
						append(
							nodeIDs,
							"persistence:"+
								sanitizeFindingID(
									finding.ID,
								),
						)

					chainNames =
						append(
							chainNames,
							finding.Name,
						)
				}
			}

			/*
				远程登录本身不能形成 Attack Chain。

				要求至少还存在：
				- shell
				- external network
				- persistence

				其中之一。
			*/

			if score <= 40 {
				continue
			}

			severity :=
				activitySeverity(
					score,
				)

			result =
				append(
					result,
					model.AttackChain{
						ID: fmt.Sprintf(
							"CHAIN-%s-%d",
							sanitizeFindingID(
								session.LogonID,
							),
							process.PID,
						),

						Title: "Correlated remote logon activity",

						Severity: severity,

						Score: score,

						NodeIDs: uniqueStrings(
							nodeIDs,
						),

						Reasons: uniqueStrings(
							reasons,
						),

						Summary: joinChainNames(
							chainNames,
						),
					},
				)
		}
	}

	return result
}
