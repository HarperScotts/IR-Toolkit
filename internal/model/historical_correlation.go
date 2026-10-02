package model

import "time"

type CorrelationEvidence struct {
	Type string `json:"type"`

	Value string `json:"value"`

	Description string `json:"description,omitempty"`
}

type CorrelationEdge struct {
	ID string `json:"id"`

	From string `json:"from"`

	To string `json:"to"`

	Type string `json:"type"`

	Confidence string `json:"confidence"`

	Score int `json:"score"`

	Basis []CorrelationEvidence `json:"basis"`

	Timestamp time.Time `json:"timestamp,omitempty"`
}

type HistoricalChainNode struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Label string `json:"label"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	SessionID string `json:"session_id,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	Object string `json:"object,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type HistoricalChain struct {
	ID string `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	Score int `json:"score"`

	Confidence string `json:"confidence"`

	StartTime time.Time `json:"start_time,omitempty"`

	EndTime time.Time `json:"end_time,omitempty"`

	NodeIDs []string `json:"node_ids"`

	EdgeIDs []string `json:"edge_ids"`

	Reasons []string `json:"reasons"`

	Summary string `json:"summary"`
}

type HistoricalCorrelationStatistics struct {
	NodeCount uint32 `json:"node_count"`

	EdgeCount uint32 `json:"edge_count"`

	HighConfidenceEdgeCount uint32 `json:"high_confidence_edge_count"`

	MediumConfidenceEdgeCount uint32 `json:"medium_confidence_edge_count"`

	LowConfidenceEdgeCount uint32 `json:"low_confidence_edge_count"`

	ChainCount uint32 `json:"chain_count"`

	CriticalChainCount uint32 `json:"critical_chain_count"`

	HighChainCount uint32 `json:"high_chain_count"`

	MediumChainCount uint32 `json:"medium_chain_count"`
}

type HistoricalCorrelationAnalysis struct {
	Nodes []HistoricalChainNode `json:"nodes"`

	Edges []CorrelationEdge `json:"edges"`

	Chains []HistoricalChain `json:"chains"`

	Statistics HistoricalCorrelationStatistics `json:"statistics"`
}
