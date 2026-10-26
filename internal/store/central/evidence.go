package central

import (
	"strconv"
	"strings"

	"ir-toolkit/internal/store"
)

func (i *Investigator) EvidenceDetail(view store.CaseView, evidenceType, id string) (store.ScopedEvidenceDetail, bool, error) {
	result := store.ScopedEvidenceDetail{View: view, Type: evidenceType, ID: id}
	if !view.Valid() {
		return result, false, store.ErrInvalidCaseView
	}
	if i == nil || i.repository == nil {
		return result, false, ErrNilRepository
	}
	snapshot, ok := i.repository.Open(view)
	if !ok {
		return result, false, store.ErrCaseViewNotFound
	}
	if id == "" {
		return result, false, store.ErrInvalidEvidenceID
	}
	var found bool
	var err error
	switch evidenceType {
	case "process":
		if !strings.HasPrefix(id, "process:") {
			return result, false, store.ErrInvalidEvidenceID
		}
		pid, parseErr := strconv.ParseUint(strings.TrimPrefix(id, "process:"), 10, 32)
		if parseErr != nil {
			return result, false, store.ErrInvalidEvidenceID
		}
		result.Evidence, found, err = snapshot.ProcessByPID(uint32(pid))
	case "login":
		if !strings.HasPrefix(id, "login:") || len(id) == len("login:") {
			return result, false, store.ErrInvalidEvidenceID
		}
		result.Evidence, found, err = snapshot.LoginByLogonID(strings.TrimPrefix(id, "login:"))
	case "file":
		if !strings.HasPrefix(id, "file:") || len(id) == len("file:") {
			return result, false, store.ErrInvalidEvidenceID
		}
		result.Evidence, found, err = snapshot.FileByPath(strings.TrimPrefix(id, "file:"))
	case "network":
		result.Evidence, found, err = snapshot.NetworkItemByID(id)
	case "persistence":
		result.Evidence, found, err = snapshot.PersistenceItemByID(id)
	case "historical_process":
		result.Evidence, found, err = snapshot.HistoricalProcessByID(id)
	case "powershell":
		result.Evidence, found, err = snapshot.PowerShellScriptBlockByID(id)
	case "windows_event":
		result.Evidence, found, err = snapshot.WindowsActivityByID(id)
	case "ioc":
		result.Evidence, found, err = snapshot.IOCMatchByID(id)
	case "timeline":
		result.Evidence, found, err = snapshot.TimelineEventByID(id)
	case "correlation_node":
		result.Evidence, found, err = snapshot.CorrelationNodeByID(id)
	case "correlation_edge":
		result.Evidence, found, err = snapshot.CorrelationEdgeByID(id)
	default:
		return result, false, store.ErrUnsupportedEvidenceType
	}
	if err != nil || !found {
		result.Evidence = nil
	}
	return result, found, err
}

var _ store.ScopedEvidenceStore = (*Investigator)(nil)
