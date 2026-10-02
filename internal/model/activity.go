package model

import "time"

type ActivityNode struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Label string `json:"label"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	Severity string `json:"severity,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}

type ActivityEdge struct {
	From string `json:"from"`

	To string `json:"to"`

	Type string `json:"type"`

	Label string `json:"label,omitempty"`
}

type AttackChain struct {
	ID string `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	Score int `json:"score"`

	NodeIDs []string `json:"node_ids"`

	Reasons []string `json:"reasons"`

	Summary string `json:"summary"`
}

type ActivityStatistics struct {
	NodeCount uint32 `json:"node_count"`

	EdgeCount uint32 `json:"edge_count"`

	LoginNodeCount uint32 `json:"login_node_count"`

	ProcessNodeCount uint32 `json:"process_node_count"`

	NetworkNodeCount uint32 `json:"network_node_count"`

	PersistenceNodeCount uint32 `json:"persistence_node_count"`

	AttackChainCount uint32 `json:"attack_chain_count"`

	CriticalChainCount uint32 `json:"critical_chain_count"`

	HighChainCount uint32 `json:"high_chain_count"`

	MediumChainCount uint32 `json:"medium_chain_count"`
}

type ActivityAnalysis struct {
	Nodes []ActivityNode `json:"nodes"`

	Edges []ActivityEdge `json:"edges"`

	Chains []AttackChain `json:"chains"`

	Statistics ActivityStatistics `json:"statistics"`
}
