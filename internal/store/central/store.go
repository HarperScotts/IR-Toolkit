package central

import (
	"errors"
	"reflect"

	"ir-toolkit/internal/store"
)

var (
	ErrInvalidView = store.ErrInvalidCaseView
	ErrNilSnapshot = errors.New("central store snapshot is required")
)

// View identifies one committed, immutable case/host analysis version.
// Evidence IDs remain scoped to this view and are not rewritten.
type View = store.CaseView

type snapshotStore interface {
	store.CaseStore
}

// CaseStore binds a committed Store snapshot to its Central identity.
//
// The embedded contract is intentionally read-only. Central ingest is
// responsible for producing and atomically publishing the snapshot; it is not
// part of this type.
type CaseStore struct {
	snapshotStore

	view View
}

func New(view View, snapshot store.CaseStore) (*CaseStore, error) {
	if !view.Valid() {
		return nil, ErrInvalidView
	}
	if isNilSnapshot(snapshot) {
		return nil, ErrNilSnapshot
	}

	return &CaseStore{
		snapshotStore: snapshot,
		view:          view,
	}, nil
}

func (s *CaseStore) View() View {
	return s.view
}

func isNilSnapshot(snapshot store.CaseStore) bool {
	if snapshot == nil {
		return true
	}

	value := reflect.ValueOf(snapshot)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ store.CaseStore = (*CaseStore)(nil)
