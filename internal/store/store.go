package store

import (
	"ir-toolkit/internal/model"
)

type CaseStore interface {
	FileStore

	PersistenceStore

	ProcessStore

	LoginStore

	NetworkStore

	TimelineStore

	HistoricalProcessStore

	PowerShellStore

	WindowsEventStore

	IOCStore

	CorrelationStore

	CaseMetadataStore

	QueryStore

	SearchStore
}

type FileStore interface {
	Files() (
		*model.FileTriageSnapshot,
		error,
	)

	FileByPath(
		path string,
	) (
		model.FileTriageItem,
		bool,
		error,
	)

	FileFindingByPath(
		path string,
	) (
		model.FileFinding,
		bool,
		error,
	)

	FileFindings() (
		map[string]model.FileFinding,
		error,
	)

	FileFindingByID(
		id string,
	) (
		model.FileFinding,
		bool,
		error,
	)
}

type PersistenceStore interface {
	PersistenceSnapshot() (
		*model.PersistenceSnapshot,
		error,
	)

	PersistenceItems() (
		[]PersistenceQueryItem,
		error,
	)

	PersistenceItemByID(
		id string,
	) (
		PersistenceQueryItem,
		bool,
		error,
	)

	PersistenceFinding(
		evidenceType string,
		name string,
	) (
		model.PersistenceFinding,
		bool,
		error,
	)

	PersistenceFindings() (
		map[string]model.PersistenceFinding,
		error,
	)

	PersistenceFindingByID(
		id string,
	) (
		model.PersistenceFinding,
		bool,
		error,
	)

	ServiceByPersistenceID(
		id string,
	) (
		model.ServiceInfo,
		bool,
		error,
	)

	RunKeyByPersistenceID(
		id string,
	) (
		model.RegistryRunEntry,
		bool,
		error,
	)

	ScheduledTaskByPersistenceID(
		id string,
	) (
		model.ScheduledTask,
		bool,
		error,
	)
}

type ProcessStore interface {
	Processes() (
		[]model.Process,
		error,
	)

	ProcessByPID(
		pid uint32,
	) (
		model.Process,
		bool,
		error,
	)

	ProcessChildren(
		pid uint32,
	) (
		[]model.Process,
		error,
	)

	ProcessesByLogonID(
		logonID string,
	) (
		[]model.Process,
		error,
	)
}

type LoginStore interface {
	LoginAnalysis() (
		*model.LoginAnalysis,
		error,
	)

	LoginSessions() (
		[]model.LoginSessionAnalysis,
		error,
	)

	LoginByLogonID(
		logonID string,
	) (
		model.LoginSessionAnalysis,
		bool,
		error,
	)
}

type NetworkStore interface {
	NetworkAnalysis() (
		*NetworkAnalysisRecord,
		error,
	)

	NetworkProcessByPID(
		pid uint32,
	) (
		ProcessNetworkRecord,
		bool,
		error,
	)

	NetworkItems() (
		[]NetworkQueryItem,
		error,
	)

	NetworkItemByID(
		id string,
	) (
		NetworkQueryItem,
		bool,
		error,
	)
}

type TimelineStore interface {
	Timeline() (
		*model.Timeline,
		error,
	)

	TimelineEvents() (
		[]model.TimelineEvent,
		error,
	)

	TimelineEventByID(
		id string,
	) (
		model.TimelineEvent,
		bool,
		error,
	)

	TimelineEventsByPID(
		pid uint32,
	) (
		[]model.TimelineEvent,
		error,
	)

	TimelineEventCountByPID(
		pid uint32,
	) (
		uint32,
		error,
	)
}

type HistoricalProcessStore interface {
	HistoricalProcesses() (
		[]HistoricalProcessRecord,
		error,
	)

	HistoricalProcessByID(
		id string,
	) (
		HistoricalProcessRecord,
		bool,
		error,
	)

	HistoricalProcessesByCurrentPID(
		pid uint32,
	) (
		[]HistoricalProcessRecord,
		error,
	)
}

type PowerShellStore interface {
	PowerShellAnalysis() (
		*model.PowerShellAnalysis,
		error,
	)

	PowerShellScriptBlocks() (
		[]model.PowerShellScriptBlock,
		error,
	)

	PowerShellScriptBlockByID(
		id string,
	) (
		model.PowerShellScriptBlock,
		bool,
		error,
	)

	PowerShellByHistoricalProcessID(
		historicalProcessID string,
	) (
		[]model.PowerShellScriptBlock,
		error,
	)
}

type WindowsEventStore interface {
	WindowsEventAnalysis() (
		*model.WindowsEventAnalysis,
		error,
	)

	WindowsActivities() (
		[]model.WindowsActivity,
		error,
	)

	WindowsActivityByID(
		id string,
	) (
		model.WindowsActivity,
		bool,
		error,
	)
}

type IOCStore interface {
	IOCScanResult() (
		*model.IOCScanResult,
		error,
	)

	IOCMatches() (
		[]model.IOCMatch,
		error,
	)

	IOCMatchByID(
		id string,
	) (
		model.IOCMatch,
		bool,
		error,
	)
}

type CorrelationStore interface {
	HistoricalCorrelation() (
		*HistoricalCorrelationRecord,
		error,
	)

	CorrelationNodes() (
		[]CorrelationNodeRecord,
		error,
	)

	CorrelationEdges() (
		[]CorrelationEdgeRecord,
		error,
	)

	CorrelationChains() (
		[]HistoricalChainRecord,
		error,
	)

	CorrelationNodeByID(
		id string,
	) (
		CorrelationNodeRecord,
		bool,
		error,
	)

	CorrelationEdgeByID(
		id string,
	) (
		CorrelationEdgeRecord,
		bool,
		error,
	)

	CorrelationChainByID(
		id string,
	) (
		HistoricalChainRecord,
		bool,
		error,
	)
}

type CaseMetadataStore interface {
	CaseName() string

	Host() (
		model.HostInfo,
		error,
	)

	Capabilities() (
		model.AuditCapabilitySnapshot,
		error,
	)

	SecurityProviders() (
		model.SecurityProviderSnapshot,
		bool,
		error,
	)

	Report() (
		model.CaseReport,
		bool,
		error,
	)
}

type QueryStore interface {
	QueryTimeline(
		options TimelineQueryOptions,
	) (
		TimelineQueryResult,
		error,
	)

	QueryProcesses(
		options ProcessQueryOptions,
	) (
		QueryResult[model.Process],
		error,
	)

	QueryLogins(
		options LoginQueryOptions,
	) (
		QueryResult[model.LoginSessionAnalysis],
		error,
	)

	QueryNetwork(
		options NetworkQueryOptions,
	) (
		QueryResult[NetworkQueryItem],
		error,
	)

	QueryFiles(
		options FileQueryOptions,
	) (
		QueryResult[FileQueryItem],
		error,
	)

	QueryPersistence(
		options PersistenceQueryOptions,
	) (
		QueryResult[PersistenceQueryItem],
		error,
	)
}

type SearchStore interface {
	SearchInvestigation(
		options InvestigationSearchOptions,
	) (
		InvestigationSearchStoreResult,
		error,
	)
}
