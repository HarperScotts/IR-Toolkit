package web

import (
	"fmt"
	"ir-toolkit/internal/store"
	"net/http"
	"sort"
	"strings"
	"time"
)

type webCorrelationEvidence struct {
	Type string `json:"type"`

	Value string `json:"value"`

	Description string `json:"description,omitempty"`
}

type webCorrelationEdge struct {
	ID string `json:"id"`

	From string `json:"from"`

	To string `json:"to"`

	Type string `json:"type"`

	Confidence string `json:"confidence,omitempty"`

	Score int `json:"score,omitempty"`

	Basis []webCorrelationEvidence `json:"basis,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`
}

type webCorrelationNode struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Label string `json:"label"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	Object string `json:"object,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type webHistoricalChain struct {
	ID string `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	Score int `json:"score"`

	Confidence string `json:"confidence"`

	StartTime time.Time `json:"start_time,omitempty"`

	EndTime time.Time `json:"end_time,omitempty"`

	NodeIDs []string `json:"node_ids"`

	EdgeIDs []string `json:"edge_ids"`

	Reasons []string `json:"reasons,omitempty"`

	Summary string `json:"summary,omitempty"`
}

type webHistoricalCorrelationAnalysis struct {
	Nodes []webCorrelationNode `json:"nodes,omitempty"`

	Edges []webCorrelationEdge `json:"edges,omitempty"`

	Chains []webHistoricalChain `json:"chains,omitempty"`
}

type CorrelationOverviewResponse struct {
	Statistics CorrelationStatistics `json:"statistics"`

	Nodes []CorrelationNodeResponse `json:"nodes"`

	Edges []CorrelationEdgeResponse `json:"edges"`

	Chains []CorrelationChainSummary `json:"chains"`
}

type CorrelationStatistics struct {
	NodeCount uint32 `json:"node_count"`

	EdgeCount uint32 `json:"edge_count"`

	ChainCount uint32 `json:"chain_count"`

	HighConfidenceEdges uint32 `json:"high_confidence_edges"`

	MediumConfidenceEdges uint32 `json:"medium_confidence_edges"`
}

type CorrelationNodeResponse struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Label string `json:"label"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	Object string `json:"object,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type CorrelationEdgeResponse struct {
	ID string `json:"id"`

	From string `json:"from"`

	To string `json:"to"`

	Type string `json:"type"`

	Confidence string `json:"confidence,omitempty"`

	Score int `json:"score,omitempty"`

	Basis []webCorrelationEvidence `json:"basis,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`
}

type CorrelationChainSummary struct {
	ID string `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	Score int `json:"score"`

	Confidence string `json:"confidence"`

	StartTime time.Time `json:"start_time,omitempty"`

	EndTime time.Time `json:"end_time,omitempty"`

	NodeCount uint32 `json:"node_count"`

	EdgeCount uint32 `json:"edge_count"`

	NodeIDs []string `json:"node_ids"`

	EdgeIDs []string `json:"edge_ids"`

	Reasons []string `json:"reasons,omitempty"`

	Summary string `json:"summary,omitempty"`
}

func correlationNodeLabel(
	node store.CorrelationNodeRecord,
) string {

	if node.Label != "" {
		return node.Label
	}

	if node.Object != "" {
		return node.Object
	}

	if node.ID != "" {
		return node.ID
	}

	return "Evidence"
}

func (s *Server) handleCorrelation(
	writer http.ResponseWriter,
	request *http.Request,
) {

	analysis,
		err :=
		s.store.HistoricalCorrelation()

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load historical correlation: %v",
				err,
			),
		)

		return
	}

	nodes :=
		make(
			[]CorrelationNodeResponse,
			0,
			len(analysis.Nodes),
		)

	for _, node := range analysis.Nodes {

		nodes =
			append(
				nodes,
				CorrelationNodeResponse{
					ID: node.ID,

					Type: node.Type,

					Label: correlationNodeLabel(node),

					Timestamp: node.Timestamp,

					User: node.User,

					LogonID: node.LogonID,

					PID: node.PID,

					Object: node.Object,

					Metadata: node.Metadata,
				},
			)
	}

	edges :=
		make(
			[]CorrelationEdgeResponse,
			0,
			len(analysis.Edges),
		)

	var high uint32
	var medium uint32

	for _, edge := range analysis.Edges {

		switch strings.ToLower(
			edge.Confidence,
		) {

		case "high":

			high++

		case "medium":

			medium++
		}

		edges =
			append(
				edges,
				CorrelationEdgeResponse{
					ID: edge.ID,

					From: edge.From,

					To: edge.To,

					Type: edge.Type,

					Confidence: edge.Confidence,

					Score: edge.Score,

					Basis: webCorrelationEvidenceListFromStore(
						edge.Basis,
					),

					Timestamp: edge.Timestamp,
				},
			)
	}

	chains :=
		make(
			[]CorrelationChainSummary,
			0,
			len(analysis.Chains),
		)

	for _, chain := range analysis.Chains {

		chains =
			append(
				chains,
				CorrelationChainSummary{
					ID: chain.ID,

					Title: chain.Title,

					Severity: chain.Severity,

					Score: chain.Score,

					Confidence: chain.Confidence,

					StartTime: chain.StartTime,

					EndTime: chain.EndTime,

					NodeCount: uint32(
						len(chain.NodeIDs),
					),

					EdgeCount: uint32(
						len(chain.EdgeIDs),
					),

					NodeIDs: append(
						[]string(nil),
						chain.NodeIDs...,
					),

					EdgeIDs: append(
						[]string(nil),
						chain.EdgeIDs...,
					),

					Reasons: append(
						[]string(nil),
						chain.Reasons...,
					),

					Summary: chain.Summary,
				},
			)
	}

	sort.SliceStable(
		chains,
		func(i, j int) bool {

			return chains[i].Score >
				chains[j].Score
		},
	)

	writeJSON(
		writer,
		http.StatusOK,
		CorrelationOverviewResponse{
			Statistics: CorrelationStatistics{
				NodeCount: uint32(
					len(nodes),
				),

				EdgeCount: uint32(
					len(edges),
				),

				ChainCount: uint32(
					len(chains),
				),

				HighConfidenceEdges: high,

				MediumConfidenceEdges: medium,
			},

			Nodes: nodes,

			Edges: edges,

			Chains: chains,
		},
	)
}

func webCorrelationEvidenceFromStore(
	evidence store.CorrelationEvidenceRecord,
) webCorrelationEvidence {

	return webCorrelationEvidence{
		Type: evidence.Type,

		Value: evidence.Value,

		Description: evidence.Description,
	}
}

func webCorrelationNodeFromStore(
	node store.CorrelationNodeRecord,
) webCorrelationNode {

	metadata :=
		make(
			map[string]string,
			len(node.Metadata),
		)

	for key, value := range node.Metadata {

		metadata[key] =
			value
	}

	return webCorrelationNode{
		ID: node.ID,

		Type: node.Type,

		Label: node.Label,

		Timestamp: node.Timestamp,

		User: node.User,

		LogonID: node.LogonID,

		PID: node.PID,

		Object: node.Object,

		Metadata: metadata,
	}
}

func webCorrelationEdgeFromStore(
	edge store.CorrelationEdgeRecord,
) webCorrelationEdge {

	basis :=
		make(
			[]webCorrelationEvidence,
			0,
			len(edge.Basis),
		)

	for _, evidence := range edge.Basis {

		basis =
			append(
				basis,
				webCorrelationEvidenceFromStore(
					evidence,
				),
			)
	}

	return webCorrelationEdge{
		ID: edge.ID,

		From: edge.From,

		To: edge.To,

		Type: edge.Type,

		Confidence: edge.Confidence,

		Score: edge.Score,

		Basis: basis,

		Timestamp: edge.Timestamp,
	}
}

func webHistoricalChainFromStore(
	chain store.HistoricalChainRecord,
) webHistoricalChain {

	return webHistoricalChain{
		ID: chain.ID,

		Title: chain.Title,

		Severity: chain.Severity,

		Score: chain.Score,

		Confidence: chain.Confidence,

		StartTime: chain.StartTime,

		EndTime: chain.EndTime,

		NodeIDs: append(
			[]string(nil),
			chain.NodeIDs...,
		),

		EdgeIDs: append(
			[]string(nil),
			chain.EdgeIDs...,
		),

		Reasons: append(
			[]string(nil),
			chain.Reasons...,
		),

		Summary: chain.Summary,
	}
}

func webHistoricalCorrelationFromStore(
	analysis *store.HistoricalCorrelationRecord,
) *webHistoricalCorrelationAnalysis {

	if analysis == nil {
		return nil
	}

	result :=
		&webHistoricalCorrelationAnalysis{
			Nodes: make(
				[]webCorrelationNode,
				0,
				len(analysis.Nodes),
			),

			Edges: make(
				[]webCorrelationEdge,
				0,
				len(analysis.Edges),
			),

			Chains: make(
				[]webHistoricalChain,
				0,
				len(analysis.Chains),
			),
		}

	for _, node := range analysis.Nodes {

		result.Nodes =
			append(
				result.Nodes,
				webCorrelationNodeFromStore(
					node,
				),
			)
	}

	for _, edge := range analysis.Edges {

		result.Edges =
			append(
				result.Edges,
				webCorrelationEdgeFromStore(
					edge,
				),
			)
	}

	for _, chain := range analysis.Chains {

		result.Chains =
			append(
				result.Chains,
				webHistoricalChainFromStore(
					chain,
				),
			)
	}

	return result
}

func webCorrelationEvidenceListFromStore(
	evidence []store.CorrelationEvidenceRecord,
) []webCorrelationEvidence {

	if len(evidence) == 0 {
		return nil
	}

	result :=
		make(
			[]webCorrelationEvidence,
			0,
			len(evidence),
		)

	for _, item := range evidence {

		result =
			append(
				result,
				webCorrelationEvidenceFromStore(
					item,
				),
			)
	}

	return result
}
