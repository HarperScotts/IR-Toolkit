package store

import (
	"ir-toolkit/internal/model"
	"time"
)

type QueryPageOptions struct {
	Offset int
	Limit  int
}

type QueryPageResult struct {
	Offset  int
	Limit   int
	HasMore bool
}

type QueryResult[T any] struct {
	Total uint32
	Page  QueryPageResult
	Items []T
}

type ProcessQueryOptions struct {
	Query string
	User  string
	PID   uint32
	Page  QueryPageOptions
}

type LoginQueryOptions struct {
	Query     string
	User      string
	IP        string
	LogonType string
	Page      QueryPageOptions
}

type NetworkQueryOptions struct {
	Query    string
	PID      uint32
	IP       string
	State    string
	External *bool
	Page     QueryPageOptions
}

type FileQueryOptions struct {
	Query      string
	Owner      string
	Extension  string
	Executable *bool
	Finding    *bool
	Page       QueryPageOptions
}

type PersistenceQueryOptions struct {
	Query   string
	Type    string
	User    string
	Finding *bool
	Page    QueryPageOptions
}

type TimelineQueryOptions struct {
	Category string
	PID      uint32
	User     string
	IP       string
	Query    string
	From     *time.Time
	To       *time.Time
	Order    string
	Page     QueryPageOptions
}

type FileQueryItem struct {
	Evidence model.FileTriageItem
	Finding  *model.FileFinding
}

type PersistenceQueryItem struct {
	ID        string
	Type      string
	Name      string
	Title     string
	Command   string
	User      string
	Object    string
	Timestamp time.Time
	PID       uint32
	Finding   *model.PersistenceFinding
}

type NetworkQueryItem struct {
	ID               string
	PID              uint32
	ProcessName      string
	ProcessPath      string
	User             string
	AuthenticationID string
	Protocol         string
	Family           string
	LocalAddress     string
	LocalPort        uint32
	RemoteAddress    string
	RemotePort       uint32
	State            string
	Kind             string
	External         bool
}

type InvestigationSearchOptions struct {
	Query string
	Types map[string]bool
	Limit int
}

type InvestigationSearchItem struct {
	Type      string
	ID        string
	Title     string
	Subtitle  string
	Timestamp time.Time
	PID       uint32
	User      string
	IP        string
	Object    string
	Match     string
	Metadata  map[string]string
}

type InvestigationSearchStoreResult struct {
	Total  uint32
	ByType map[string]uint32
	Items  []InvestigationSearchItem
}

type TimelineQueryResult struct {
	Total          uint32
	Page           QueryPageResult
	CategoryCounts map[string]uint32
	Events         []model.TimelineEvent
}
