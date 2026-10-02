package store

import (
	"errors"
	"strings"

	"ir-toolkit/internal/model"
)

var (
	ErrInvalidCaseView   = errors.New("case view requires case ID, host ID, and version")
	ErrDuplicateCaseView = errors.New("duplicate case view")
	ErrCaseViewNotFound  = errors.New("case view not found")
	ErrMixedCases        = errors.New("multi-host investigation requires one case")
)

type CaseView struct {
	CaseID  string `json:"case_id"`
	HostID  string `json:"host_id"`
	Version string `json:"version"`
}

func (v CaseView) Valid() bool {
	return strings.TrimSpace(v.CaseID) != "" &&
		strings.TrimSpace(v.HostID) != "" &&
		strings.TrimSpace(v.Version) != ""
}

type MultiHostSearchOptions struct {
	Views  []CaseView
	Search InvestigationSearchOptions
}

type MultiHostSearchItem struct {
	View CaseView
	Item InvestigationSearchItem
}

type MultiHostViewSearchSummary struct {
	View   CaseView
	Total  uint32
	ByType map[string]uint32
}

type MultiHostSearchResult struct {
	Total  uint64
	ByType map[string]uint64
	ByView []MultiHostViewSearchSummary
	Items  []MultiHostSearchItem
}

type MultiHostTimelineOptions struct {
	Views []CaseView
	Query TimelineQueryOptions
}

type MultiHostTimelineEvent struct {
	View  CaseView
	Event model.TimelineEvent
}

type MultiHostTimelineViewSummary struct {
	View           CaseView
	Total          uint32
	CategoryCounts map[string]uint32
}

type MultiHostTimelineResult struct {
	Total          uint64
	Page           QueryPageResult
	CategoryCounts map[string]uint64
	ByView         []MultiHostTimelineViewSummary
	Events         []MultiHostTimelineEvent
}

type MultiHostInvestigationStore interface {
	SearchInvestigation(
		options MultiHostSearchOptions,
	) (
		MultiHostSearchResult,
		error,
	)

	QueryTimeline(
		options MultiHostTimelineOptions,
	) (
		MultiHostTimelineResult,
		error,
	)
}
