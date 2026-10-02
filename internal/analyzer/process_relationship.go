package analyzer

import (
	"context"
	"fmt"
	"ir-toolkit/internal/model"
)

func AnalyzeProcessRelationships(
	ctx context.Context,
	processes []model.Process,
	network model.NetworkAnalysis,
) model.ProcessRelationshipAnalysis {

	result := model.ProcessRelationshipAnalysis{
		Processes: make(
			[]model.ProcessRelationship,
			0,
			len(processes),
		),

		Findings: make(
			[]model.RelationshipFinding,
			0,
		),
	}

	processMap := make(
		map[uint32]model.Process,
		len(processes),
	)

	relationIndex := make(
		map[uint32]int,
		len(processes),
	)

	networkMap := make(
		map[uint32]model.ProcessNetworkAnalysis,
		len(network.Processes),
	)

	for _, item := range network.Processes {
		networkMap[item.PID] = item
	}

	// --------------------------------------------------
	// Process index
	// --------------------------------------------------

	for _, process := range processes {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		processMap[process.PID] =
			process

		relation := model.ProcessRelationship{
			PID: process.PID,

			PPID: process.PPID,

			Name: process.Name,

			Path: process.Path,

			CommandLine: process.CommandLine,

			User: process.User,

			IntegrityLevel: process.IntegrityLevel,
		}

		if netInfo, exists :=
			networkMap[process.PID]; exists {

			relation.Connections =
				netInfo.Connections

			relation.ExternalConnections =
				netInfo.ExternalConnections
		}

		index := len(result.Processes)

		result.Processes = append(
			result.Processes,
			relation,
		)

		relationIndex[process.PID] =
			index
	}

	// --------------------------------------------------
	// Parent / Child
	// --------------------------------------------------

	for _, process := range processes {

		index :=
			relationIndex[process.PID]

		relation :=
			&result.Processes[index]

		parent, exists :=
			processMap[process.PPID]

		if !exists {
			continue
		}

		relation.Parent =
			&model.ProcessRef{
				PID: parent.PID,

				Name: parent.Name,

				Path: parent.Path,
			}

		parentIndex, exists :=
			relationIndex[parent.PID]

		if exists {

			result.Processes[parentIndex].
				Children =
				append(
					result.Processes[parentIndex].
						Children,

					model.ProcessRef{
						PID: process.PID,

						Name: process.Name,

						Path: process.Path,
					},
				)

			result.Statistics.
				ParentChildRelations++
		}
	}

	// --------------------------------------------------
	// Relationship indicators
	// --------------------------------------------------

	for i := range result.Processes {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		item :=
			&result.Processes[i]

		result.Statistics.ProcessCount++

		if len(
			item.ExternalConnections,
		) > 0 {

			result.Statistics.
				ProcessesWithExternalNetwork++
		}

		indicators, findings :=
			analyzeRelationship(
				item,
				processMap,
			)

		item.Indicators =
			append(
				item.Indicators,
				indicators...,
			)

		result.Findings =
			append(
				result.Findings,
				findings...,
			)
	}

	result.Statistics.Findings =
		uint32(
			len(result.Findings),
		)

	return result
}

func analyzeRelationship(
	process *model.ProcessRelationship,
	processMap map[uint32]model.Process,
) ([]string, []model.RelationshipFinding) {

	indicators := make(
		[]string,
		0,
	)

	findings := make(
		[]model.RelationshipFinding,
		0,
	)

	parent, parentExists :=
		processMap[process.PPID]

	// --------------------------------------------------
	// Web Server -> Shell
	// --------------------------------------------------

	if parentExists &&
		isWebServerProcess(parent) &&
		isShellProcessName(
			process.Name,
		) {

		indicator :=
			"webserver_shell_child"

		indicators =
			append(
				indicators,
				indicator,
			)

		findings =
			append(
				findings,
				model.RelationshipFinding{
					ID: fmt.Sprintf(
						"REL-WEB-SHELL-%d",
						process.PID,
					),

					Severity: "high",

					Indicator: indicator,

					Title: "Web server spawned command shell",

					PID: process.PID,

					RelatedPIDs: []uint32{
						parent.PID,
						process.PID,
					},

					Evidence: []string{
						fmt.Sprintf(
							"%s(%d) -> %s(%d)",
							parent.Name,
							parent.PID,
							process.Name,
							process.PID,
						),
					},
				},
			)
	}

	// --------------------------------------------------
	// Shell -> scripting/download utility
	// --------------------------------------------------

	if parentExists &&
		isShellProcessName(
			parent.Name,
		) &&
		isScriptOrTransferProcess(
			process.Name,
		) {

		indicator :=
			"shell_spawned_script_or_transfer_tool"

		indicators =
			append(
				indicators,
				indicator,
			)

		findings =
			append(
				findings,
				model.RelationshipFinding{
					ID: fmt.Sprintf(
						"REL-SHELL-TOOL-%d",
						process.PID,
					),

					Severity: "medium",

					Indicator: indicator,

					Title: "Shell spawned script or transfer utility",

					PID: process.PID,

					RelatedPIDs: []uint32{
						parent.PID,
						process.PID,
					},

					Evidence: []string{
						fmt.Sprintf(
							"%s(%d) -> %s(%d)",
							parent.Name,
							parent.PID,
							process.Name,
							process.PID,
						),
					},
				},
			)
	}

	// --------------------------------------------------
	// Web ancestor + Shell + Public Network
	// --------------------------------------------------

	if len(
		process.ExternalConnections,
	) > 0 {

		chain :=
			buildAncestorChain(
				process.PID,
				processMap,
			)

		if chainHasWebServer(
			chain,
		) &&
			chainHasShell(
				chain,
			) {

			indicator :=
				"webserver_shell_external_network"

			indicators =
				append(
					indicators,
					indicator,
				)

			findings =
				append(
					findings,
					model.RelationshipFinding{
						ID: fmt.Sprintf(
							"REL-WEB-NET-%d",
							process.PID,
						),

						Severity: "high",

						Indicator: indicator,

						Title: "Web-originated process chain has external network connection",

						PID: process.PID,

						RelatedPIDs: processIDs(
							chain,
						),

						Evidence: []string{
							formatProcessChain(
								chain,
							),
						},
					},
				)
		}
	}

	return uniqueStrings(
			indicators,
		),
		findings
}
