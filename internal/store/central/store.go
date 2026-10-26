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

// CaseStore binds a committed Store snapshot to its Central identity.
//
// Results are caller-owned copies. The source must already be a committed,
// immutable snapshot, safe for concurrent reads; New does not freeze a live
// Store. Its owner must not mutate it or its previously returned values after
// publication. Preparing that snapshot is separate from atomic publication.
type CaseStore struct {
	snapshot store.CaseStore
	view     View
}

func New(view View, snapshot store.CaseStore) (*CaseStore, error) {
	if !view.Valid() {
		return nil, ErrInvalidView
	}
	if isNilSnapshot(snapshot) {
		return nil, ErrNilSnapshot
	}

	return &CaseStore{
		snapshot: snapshot,
		view:     view,
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
