package analyzer

import (
	"context"
	"fmt"
	"strconv"

	"ir-toolkit/internal/model"
)

func AnalyzeActivity(
	ctx context.Context,
	login model.LoginAnalysis,
	relationships model.ProcessRelationshipAnalysis,
	network model.NetworkAnalysis,
	persistence model.PersistenceAnalysis,
) model.ActivityAnalysis {

	result := model.ActivityAnalysis{
		Nodes: make(
			[]model.ActivityNode,
			0,
		),

		Edges: make(
			[]model.ActivityEdge,
			0,
		),

		Chains: make(
			[]model.AttackChain,
			0,
		),
	}

	nodeSeen := make(
		map[string]struct{},
	)

	edgeSeen := make(
		map[string]struct{},
	)

	processNodeMap := make(
		map[uint32]string,
	)

	loginNodeMap := make(
		map[string]string,
	)

	// --------------------------------------------------
	// Login nodes
	// --------------------------------------------------

	for _, session := range login.Sessions {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		if session.LogonID == "" {
			continue
		}

		id :=
			"login:" +
				normalizeLogonID(
					session.LogonID,
				)

		loginNodeMap[normalizeLogonID(
			session.LogonID,
		)] = id

		addActivityNode(
			&result,
			nodeSeen,
			model.ActivityNode{
				ID: id,

				Type: "login_session",

				Label: formatLoginLabel(
					session,
				),

				Timestamp: session.Timestamp,

				Metadata: map[string]string{
					"user": session.User,

					"domain": session.Domain,

					"source_ip": session.SourceIP,

					"logon_type": session.
						LogonTypeName,

					"logon_id": session.LogonID,

					"privileged": strconv.FormatBool(
						session.Privileged,
					),
				},
			},
		)
	}

	// --------------------------------------------------
	// Process nodes
	// --------------------------------------------------

	for _, process := range relationships.Processes {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		id :=
			fmt.Sprintf(
				"process:%d",
				process.PID,
			)

		processNodeMap[process.PID] = id

		addActivityNode(
			&result,
			nodeSeen,
			model.ActivityNode{
				ID: id,

				Type: "process",

				Label: fmt.Sprintf(
					"%s (%d)",
					process.Name,
					process.PID,
				),

				Metadata: map[string]string{
					"pid": strconv.FormatUint(
						uint64(
							process.PID,
						),
						10,
					),

					"ppid": strconv.FormatUint(
						uint64(
							process.PPID,
						),
						10,
					),

					"path": process.Path,

					"command_line": process.CommandLine,

					"user": process.User,

					"integrity": process.
						IntegrityLevel,
				},
			},
		)
	}

	// --------------------------------------------------
	// Parent -> Child edges
	// --------------------------------------------------

	for _, process := range relationships.Processes {

		if process.Parent == nil {
			continue
		}

		parentID, parentExists :=
			processNodeMap[process.Parent.PID]

		childID, childExists :=
			processNodeMap[process.PID]

		if !parentExists ||
			!childExists {

			continue
		}

		addActivityEdge(
			&result,
			edgeSeen,
			model.ActivityEdge{
				From: parentID,

				To: childID,

				Type: "parent_child",

				Label: "spawned",
			},
		)
	}

	// --------------------------------------------------
	// Login Session -> Process
	// --------------------------------------------------

	for _, session := range login.Sessions {

		logonID :=
			normalizeLogonID(
				session.LogonID,
			)

		loginNodeID, exists :=
			loginNodeMap[logonID]

		if !exists {
			continue
		}

		for _, process := range session.Processes {

			processNodeID, exists :=
				processNodeMap[process.PID]

			if !exists {
				continue
			}

			addActivityEdge(
				&result,
				edgeSeen,
				model.ActivityEdge{
					From: loginNodeID,

					To: processNodeID,

					Type: "session_process",

					Label: "authenticated session",
				},
			)
		}
	}
	// --------------------------------------------------
	// Process -> External Network
	// --------------------------------------------------

	for _, process := range network.Processes {

		processNodeID, exists :=
			processNodeMap[process.PID]

		if !exists {
			continue
		}

		for _, connection := range process.ExternalConnections {

			networkNodeID :=
				networkNodeID(
					process.PID,
					connection,
				)

			label :=
				fmt.Sprintf(
					"%s %s:%d",
					connection.Protocol,
					connection.RemoteAddress,
					connection.RemotePort,
				)

			addActivityNode(
				&result,
				nodeSeen,
				model.ActivityNode{
					ID: networkNodeID,

					Type: "network",

					Label: label,

					Metadata: map[string]string{
						"protocol": connection.Protocol,

						"family": connection.Family,

						"local": fmt.Sprintf(
							"%s:%d",
							connection.
								LocalAddress,
							connection.
								LocalPort,
						),

						"remote": fmt.Sprintf(
							"%s:%d",
							connection.
								RemoteAddress,
							connection.
								RemotePort,
						),

						"state": connection.State,
					},
				},
			)

			addActivityEdge(
				&result,
				edgeSeen,
				model.ActivityEdge{
					From: processNodeID,

					To: networkNodeID,

					Type: "network_connection",

					Label: connection.State,
				},
			)
		}
	}
	// --------------------------------------------------
	// Persistence findings
	// --------------------------------------------------

	for _, finding := range persistence.Findings {

		persistenceNodeID :=
			"persistence:" +
				sanitizeFindingID(
					finding.ID,
				)

		addActivityNode(
			&result,
			nodeSeen,
			model.ActivityNode{
				ID: persistenceNodeID,

				Type: "persistence",

				Label: finding.Name,

				Severity: finding.Severity,

				Metadata: map[string]string{
					"finding_id": finding.ID,

					"type": finding.Type,

					"title": finding.Title,

					"command": finding.Command,

					"executable": finding.
						ExecutablePath,

					"user": finding.User,

					"score": strconv.Itoa(
						finding.Score,
					),
				},
			},
		)

		if finding.RelatedPID == 0 {
			continue
		}

		processNodeID, exists :=
			processNodeMap[finding.RelatedPID]

		if !exists {
			continue
		}

		addActivityEdge(
			&result,
			edgeSeen,
			model.ActivityEdge{
				From: persistenceNodeID,

				To: processNodeID,

				Type: "associated_process",

				Label: "related process",
			},
		)
	}
	// --------------------------------------------------
	// Build high-value chains
	// --------------------------------------------------

	result.Chains =
		buildAttackChains(
			login,
			relationships,
			persistence,
		)

	for _, chain := range result.Chains {

		switch chain.Severity {

		case "critical":

			result.Statistics.
				CriticalChainCount++

		case "high":

			result.Statistics.
				HighChainCount++

		case "medium":

			result.Statistics.
				MediumChainCount++
		}
	}

	result.Statistics.NodeCount =
		uint32(
			len(result.Nodes),
		)

	result.Statistics.EdgeCount =
		uint32(
			len(result.Edges),
		)

	result.Statistics.AttackChainCount =
		uint32(
			len(result.Chains),
		)

	for _, node := range result.Nodes {

		switch node.Type {

		case "login_session":

			result.Statistics.
				LoginNodeCount++

		case "process":

			result.Statistics.
				ProcessNodeCount++

		case "network":

			result.Statistics.
				NetworkNodeCount++

		case "persistence":

			result.Statistics.
				PersistenceNodeCount++
		}
	}

	return result
}
