package model

type ProcessNode struct {
	Process

	Children []*ProcessNode `json:"children,omitempty"`
}

type ProcessTree struct {
	Roots []*ProcessNode `json:"roots"`
}