package central

import (
	"errors"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type processEvidenceSnapshot struct {
	store.CaseStore
	process model.Process
	err     error
}

func (s *processEvidenceSnapshot) ProcessByPID(pid uint32) (model.Process, bool, error) {
	return s.process, pid == s.process.PID, s.err
}

func TestScopedEvidenceKeepsHostVersionIdentity(t *testing.T) {
	first := View{CaseID: "case", HostID: "alpha", Version: "1"}
	second := View{CaseID: "case", HostID: "beta", Version: "1"}
	failed := View{CaseID: "case", HostID: "beta", Version: "2"}
	backendError := errors.New("unavailable")
	repository, _ := NewRepository()
	_, err := repository.IngestBatch(
		IngestRequest{View: first, Snapshot: &processEvidenceSnapshot{process: model.Process{PID: 42, Name: "alpha.exe"}}},
		IngestRequest{View: second, Snapshot: &processEvidenceSnapshot{process: model.Process{PID: 42, Name: "beta.exe"}}},
		IngestRequest{View: failed, Snapshot: &processEvidenceSnapshot{err: backendError}},
	)
	if err != nil {
		t.Fatal(err)
	}
	investigator, _ := NewInvestigator(repository)
	for _, tt := range []struct {
		view View
		name string
	}{{first, "alpha.exe"}, {second, "beta.exe"}} {
		result, found, err := investigator.EvidenceDetail(tt.view, "process", "process:42")
		if err != nil || !found {
			t.Fatalf("lookup = %v, %v", found, err)
		}
		if result.View != tt.view || result.ID != "process:42" || result.Evidence.(model.Process).Name != tt.name {
			t.Fatalf("wrong source: %#v", result)
		}
	}
	if _, found, err := investigator.EvidenceDetail(first, "process", "process:43"); found || err != nil {
		t.Fatalf("missing evidence = %v, %v", found, err)
	}
	if result, _, err := investigator.EvidenceDetail(failed, "process", "process:42"); !errors.Is(err, backendError) || result.Evidence != nil {
		t.Fatalf("backend failure = %#v, %v", result, err)
	}
	if _, _, err := investigator.EvidenceDetail(View{CaseID: "case", HostID: "missing", Version: "1"}, "process", "process:42"); !errors.Is(err, store.ErrCaseViewNotFound) {
		t.Fatal(err)
	}
	if _, _, err := investigator.EvidenceDetail(first, "process", "42"); !errors.Is(err, store.ErrInvalidEvidenceID) {
		t.Fatal(err)
	}
	if _, _, err := investigator.EvidenceDetail(first, "unknown", "id"); !errors.Is(err, store.ErrUnsupportedEvidenceType) {
		t.Fatal(err)
	}
}
