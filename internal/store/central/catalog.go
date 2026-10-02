package central

import (
	"errors"

	"ir-toolkit/internal/store"
)

var (
	ErrNilCaseStore  = errors.New("central catalog case store is required")
	ErrDuplicateView = store.ErrDuplicateCaseView
)

// Catalog is an immutable collection of committed Central views.
// Publishing or replacing views belongs to the later ingest boundary.
type Catalog struct {
	stores map[View]*CaseStore
}

func NewCatalog(stores ...*CaseStore) (*Catalog, error) {
	catalog := &Catalog{
		stores: make(map[View]*CaseStore, len(stores)),
	}

	for _, caseStore := range stores {
		if caseStore == nil {
			return nil, ErrNilCaseStore
		}

		view := caseStore.View()
		if _, exists := catalog.stores[view]; exists {
			return nil, ErrDuplicateView
		}

		catalog.stores[view] = caseStore
	}

	return catalog, nil
}

func (c *Catalog) Open(view View) (*CaseStore, bool) {
	if c == nil {
		return nil, false
	}

	caseStore, ok := c.stores[view]
	return caseStore, ok
}

func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}

	return len(c.stores)
}
