package local

import (
	"strings"
	"sync"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type PersistenceItem struct {
	ID         string
	Type       string
	Name       string
	Title      string
	Command    string
	User       string
	Object     string
	Timestamp  time.Time
	PID        uint32
	FindingID  string
	HasFinding bool
}

type NetworkItem struct {
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

func New(
	caseDir string,
) *CaseStore {

	return &CaseStore{
		caseDir: caseDir,
	}
}

type CaseStore struct {
	caseDir string

	// --------------------------------------------------
	// File domain
	// --------------------------------------------------

	fileOnce sync.Once

	fileErr error

	fileSnapshot model.FileTriageSnapshot

	fileAnalysis model.FileAnalysis

	fileByPath map[string]int

	fileFindingByPath map[string]model.FileFinding

	fileFindingByID map[string]model.FileFinding

	// --------------------------------------------------
	// Persistence domain
	// --------------------------------------------------

	persistenceOnce sync.Once

	persistenceErr error

	persistenceSnapshot model.PersistenceSnapshot

	persistenceAnalysis model.PersistenceAnalysis

	persistenceItems []PersistenceItem

	persistenceByID map[string]int

	persistenceFindingByKey map[string]model.PersistenceFinding

	persistenceFindingByID map[string]model.PersistenceFinding

	serviceByPersistenceID map[string]int

	runKeyByPersistenceID map[string]int

	scheduledTaskByPersistenceID map[string]int

	// --------------------------------------------------
	// Process domain
	// --------------------------------------------------

	processOnce sync.Once

	processErr error

	processes []model.Process

	processByPID map[uint32]int

	processChildrenByPPID map[uint32][]int

	processByAuthenticationID map[string][]int

	// --------------------------------------------------
	// Login domain
	// --------------------------------------------------

	loginOnce sync.Once

	loginErr error

	loginAnalysis model.LoginAnalysis

	loginByLogonID map[string]int

	// --------------------------------------------------
	// Network domain
	// --------------------------------------------------

	networkOnce sync.Once

	networkErr error

	networkAnalysis store.NetworkAnalysisRecord

	networkProcessByPID map[uint32]int

	networkItems []NetworkItem

	networkByID map[string]int

	// --------------------------------------------------
	// Timeline domain
	// --------------------------------------------------

	timelineOnce sync.Once

	timelineErr error

	timeline model.Timeline

	timelineByID map[string]int

	timelineByPID map[uint32][]int

	// --------------------------------------------------
	// Historical Process domain
	// --------------------------------------------------

	historicalOnce sync.Once

	historicalErr error

	historicalByID map[string]int

	historicalByCurrentPID map[uint32][]int

	historicalAnalysis store.ProcessHistoryRecord

	// --------------------------------------------------
	// PowerShell domain
	// --------------------------------------------------

	powershellOnce sync.Once

	powershellErr error

	powershellAnalysis model.PowerShellAnalysis

	powershellByID map[string]int

	powershellByHistoricalProcessID map[string][]int

	// --------------------------------------------------
	// Windows Event domain
	// --------------------------------------------------

	windowsEventOnce sync.Once

	windowsEventErr error

	windowsEventAnalysis model.WindowsEventAnalysis

	windowsEventByID map[string]int

	// --------------------------------------------------
	// IOC domain
	// --------------------------------------------------

	iocOnce sync.Once

	iocErr error

	iocScanResult model.IOCScanResult

	iocByID map[string]int

	// --------------------------------------------------
	// Historical Correlation domain
	// --------------------------------------------------

	correlationOnce sync.Once

	correlationErr error

	correlationNodeByID map[string]int

	correlationEdgeByID map[string]int

	correlationChainByID map[string]int

	correlationAnalysis store.HistoricalCorrelationRecord

	// --------------------------------------------------
	// Case Overview domain
	// --------------------------------------------------

	hostOnce sync.Once

	hostErr error

	host model.HostInfo

	capabilitiesOnce sync.Once

	capabilitiesErr error

	capabilities model.AuditCapabilitySnapshot

	securityProvidersOnce sync.Once

	securityProvidersErr error

	securityProvidersFound bool

	securityProviders model.SecurityProviderSnapshot

	reportOnce sync.Once

	reportErr error

	reportFound bool

	report model.CaseReport
}

var (
	_ store.FileStore              = (*CaseStore)(nil)
	_ store.PersistenceStore       = (*CaseStore)(nil)
	_ store.ProcessStore           = (*CaseStore)(nil)
	_ store.LoginStore             = (*CaseStore)(nil)
	_ store.NetworkStore           = (*CaseStore)(nil)
	_ store.TimelineStore          = (*CaseStore)(nil)
	_ store.HistoricalProcessStore = (*CaseStore)(nil)
	_ store.PowerShellStore        = (*CaseStore)(nil)
	_ store.WindowsEventStore      = (*CaseStore)(nil)
	_ store.IOCStore               = (*CaseStore)(nil)
	_ store.CorrelationStore       = (*CaseStore)(nil)
	_ store.CaseMetadataStore      = (*CaseStore)(nil)
	_ store.QueryStore             = (*CaseStore)(nil)
	_ store.SearchStore            = (*CaseStore)(nil)
	_ store.CaseStore              = (*CaseStore)(nil)
)

func normalizeLogonID(
	value string,
) string {

	value =
		strings.TrimSpace(
			strings.ToLower(
				value,
			),
		)

	value =
		strings.TrimPrefix(
			value,
			"0x",
		)

	value =
		strings.TrimLeft(
			value,
			"0",
		)

	if value == "" {
		value = "0"
	}

	return value
}
