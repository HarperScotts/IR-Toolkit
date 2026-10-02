package central

import (
	"errors"
	"sync"

	"ir-toolkit/internal/store"
)

var ErrNilRepository = errors.New("central repository is required")

// IngestRequest contains one complete, committed Store snapshot. Producing the
// snapshot and transporting it from an Agent are separate boundaries.
type IngestRequest struct {
	View     View
	Snapshot store.CaseStore
}

// Repository atomically publishes immutable Central views. A published view
// is never replaced; a new analysis must use a new version.
type Repository struct {
	mu     sync.RWMutex
	stores map[View]*CaseStore
}

func NewRepository(initial ...*CaseStore) (*Repository, error) {
	catalog, err := NewCatalog(initial...)
	if err != nil {
		return nil, err
	}

	stores := make(map[View]*CaseStore, len(catalog.stores))
	for view, caseStore := range catalog.stores {
		stores[view] = caseStore
	}

	return &Repository{stores: stores}, nil
}

func (r *Repository) Ingest(request IngestRequest) (*CaseStore, error) {
	stores, err := r.IngestBatch(request)
	if err != nil {
		return nil, err
	}

	return stores[0], nil
}

// IngestBatch validates the whole batch before publishing any view. Readers
// observe either the repository state before the batch or the complete batch.
func (r *Repository) IngestBatch(requests ...IngestRequest) ([]*CaseStore, error) {
	if r == nil {
		return nil, ErrNilRepository
	}

	prepared := make([]*CaseStore, 0, len(requests))
	batchViews := make(map[View]struct{}, len(requests))
	for _, request := range requests {
		caseStore, err := New(request.View, request.Snapshot)
		if err != nil {
			return nil, err
		}
		if _, duplicate := batchViews[request.View]; duplicate {
			return nil, ErrDuplicateView
		}

		batchViews[request.View] = struct{}{}
		prepared = append(prepared, caseStore)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stores == nil {
		r.stores = make(map[View]*CaseStore, len(prepared))
	}

	for view := range batchViews {
		if _, duplicate := r.stores[view]; duplicate {
			return nil, ErrDuplicateView
		}
	}

	for _, caseStore := range prepared {
		r.stores[caseStore.View()] = caseStore
	}

	return prepared, nil
}

func (r *Repository) Open(view View) (*CaseStore, bool) {
	if r == nil {
		return nil, false
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	caseStore, ok := r.stores[view]
	return caseStore, ok
}

func (r *Repository) Len() int {
	if r == nil {
		return 0
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.stores)
}

// Catalog returns an immutable point-in-time catalog of published views.
func (r *Repository) Catalog() (*Catalog, error) {
	if r == nil {
		return nil, ErrNilRepository
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	stores := make([]*CaseStore, 0, len(r.stores))
	for _, caseStore := range r.stores {
		stores = append(stores, caseStore)
	}

	return NewCatalog(stores...)
}
