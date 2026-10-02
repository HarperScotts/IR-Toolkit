package analyzer

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

func buildHistoricalCorrelationChains(
	analysis model.HistoricalCorrelationAnalysis,
) []model.HistoricalChain {

	nodeMap :=
		make(
			map[string]model.HistoricalChainNode,
		)

	for _, node := range analysis.Nodes {

		nodeMap[node.ID] =
			node
	}

	outgoing :=
		make(
			map[string][]model.CorrelationEdge,
		)

	for _, edge := range analysis.Edges {

		outgoing[edge.From] =
			append(
				outgoing[edge.From],
				edge,
			)
	}

	result :=
		make(
			[]model.HistoricalChain,
			0,
		)

	for _, node := range analysis.Nodes {

		/*
			优先从 remote login session 开始。
		*/
		if node.Type != "login" ||
			node.SourceIP == "" {

			continue
		}

		nodeIDs :=
			make(
				[]string,
				0,
			)

		edgeIDs :=
			make(
				[]string,
				0,
			)

		reasons :=
			make(
				[]string,
				0,
			)

		visited :=
			make(
				map[string]struct{},
			)

		score := 20

		walkHistoricalChain(
			node.ID,
			outgoing,
			nodeMap,
			visited,
			&nodeIDs,
			&edgeIDs,
			&reasons,
			&score,
			0,
		)

		if len(nodeIDs) < 2 {
			continue
		}

		/*
			只有 remote login + 普通 process
			还不够构成值得输出的 chain。
		*/
		if score < 40 {
			continue
		}

		start,
			end :=
			historicalChainTimeRange(
				nodeIDs,
				nodeMap,
			)

		confidence :=
			historicalChainConfidence(
				edgeIDs,
				analysis.Edges,
			)

		result =
			append(
				result,

				model.HistoricalChain{
					ID: fmt.Sprintf(
						"HCHAIN-%s",
						sanitizeFindingID(
							node.ID,
						),
					),

					Title: "Correlated historical remote activity",

					Severity: correlationSeverity(
						score,
					),

					Score: score,

					Confidence: confidence,

					StartTime: start,

					EndTime: end,

					NodeIDs: uniqueStrings(
						nodeIDs,
					),

					EdgeIDs: uniqueStrings(
						edgeIDs,
					),

					Reasons: uniqueStrings(
						reasons,
					),

					Summary: historicalChainSummary(
						nodeIDs,
						nodeMap,
					),
				},
			)
	}

	sort.SliceStable(
		result,
		func(i, j int) bool {

			return result[i].
				Score >
				result[j].
					Score
		},
	)

	return result
}

func walkHistoricalChain(
	current string,
	outgoing map[string][]model.CorrelationEdge,
	nodeMap map[string]model.HistoricalChainNode,
	visited map[string]struct{},
	nodeIDs *[]string,
	edgeIDs *[]string,
	reasons *[]string,
	score *int,
	depth int,
) {

	if depth > 16 {
		return
	}

	if _, exists :=
		visited[current]; exists {

		return
	}

	visited[current] =
		struct{}{}

	*nodeIDs =
		append(
			*nodeIDs,
			current,
		)

	node, exists :=
		nodeMap[current]

	if exists {

		switch node.Type {

		case "powershell":

			*score += 20

			*reasons =
				append(
					*reasons,
					"remote activity reached a PowerShell script block",
				)

		case "scheduled_task":

			*score += 20

			*reasons =
				append(
					*reasons,
					"remote activity is correlated with scheduled task activity",
				)

		case "wmi":

			*score += 15

			*reasons =
				append(
					*reasons,
					"remote activity is correlated with WMI activity",
				)
		}
	}

	for _, edge := range outgoing[current] {

		/*
			极低置信度边不进入自动 Chain。
		*/
		if edge.Confidence == "low" {
			continue
		}

		*edgeIDs =
			append(
				*edgeIDs,
				edge.ID,
			)

		switch edge.Type {

		case "rdp_login":

			*score += 15

		case "logon_process":

			*score += 15

		case "parent_child":

			*score += 5

		case "process_powershell":

			*score += 20

		case "process_windows_event":

			*score += 10
		}

		walkHistoricalChain(
			edge.To,
			outgoing,
			nodeMap,
			visited,
			nodeIDs,
			edgeIDs,
			reasons,
			score,
			depth+1,
		)
	}
}

func historicalChainConfidence(
	edgeIDs []string,
	edges []model.CorrelationEdge,
) string {

	if len(edgeIDs) == 0 {
		return "low"
	}

	index :=
		make(
			map[string]model.CorrelationEdge,
		)

	for _, edge := range edges {

		index[edge.ID] =
			edge
	}

	result :=
		"high"

	for _, id := range edgeIDs {

		edge, exists :=
			index[id]

		if !exists {
			continue
		}

		switch edge.Confidence {

		case "low":

			return "low"

		case "medium":

			result =
				"medium"
		}
	}

	return result
}

func historicalChainTimeRange(
	nodeIDs []string,
	nodes map[string]model.HistoricalChainNode,
) (
	time.Time,
	time.Time,
) {

	var start time.Time
	var end time.Time

	for _, id := range nodeIDs {

		node, exists :=
			nodes[id]

		if !exists ||
			node.Timestamp.IsZero() {

			continue
		}

		if start.IsZero() ||
			node.Timestamp.Before(
				start,
			) {

			start =
				node.Timestamp
		}

		if end.IsZero() ||
			node.Timestamp.After(
				end,
			) {

			end =
				node.Timestamp
		}
	}

	return start, end
}

func historicalChainSummary(
	nodeIDs []string,
	nodes map[string]model.HistoricalChainNode,
) string {

	values :=
		make(
			[]string,
			0,
		)

	for _, id := range nodeIDs {

		node, exists :=
			nodes[id]

		if !exists {
			continue
		}

		label :=
			strings.TrimSpace(
				node.Label,
			)

		if label == "" {
			label =
				node.Type
		}

		values =
			append(
				values,
				label,
			)
	}

	return strings.Join(
		values,
		" -> ",
	)
}
