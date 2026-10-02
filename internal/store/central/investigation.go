package central

import (
	"fmt"
	"sort"

	"ir-toolkit/internal/store"
)

const (
	defaultInvestigationLimit = 100
	maxInvestigationLimit     = 500
)

var (
	ErrViewNotFound = store.ErrCaseViewNotFound
	ErrMixedCases   = store.ErrMixedCases
)

// InvestigationSearchOptions selects exact committed host views. Explicit
// views avoid an implicit "latest" policy and make a result reproducible.
type InvestigationSearchOptions = store.MultiHostSearchOptions

// InvestigationSearchItem scopes an existing evidence item without changing
// its backend-neutral ID.
type InvestigationSearchItem = store.MultiHostSearchItem

type InvestigationViewSummary = store.MultiHostViewSearchSummary

type MultiHostSearchResult = store.MultiHostSearchResult

// Investigator performs read-only queries across committed Central views.
// It does not contact Agents or create relationships.
type Investigator struct {
	repository *Repository
}

func NewInvestigator(repository *Repository) (*Investigator, error) {
	if repository == nil {
		return nil, ErrNilRepository
	}

	return &Investigator{repository: repository}, nil
}

func (i *Investigator) SearchInvestigation(
	options InvestigationSearchOptions,
) (MultiHostSearchResult, error) {
	result := MultiHostSearchResult{
		ByType: make(map[string]uint64),
		ByView: make([]InvestigationViewSummary, 0, len(options.Views)),
		Items:  make([]InvestigationSearchItem, 0),
	}
	if i == nil || i.repository == nil {
		return result, ErrNilRepository
	}
	if err := validateInvestigationViews(options.Views); err != nil {
		return result, err
	}

	limit := normalizeInvestigationLimit(options.Search.Limit)
	searchOptions := options.Search
	searchOptions.Limit = limit

	for _, view := range options.Views {
		caseStore, ok := i.repository.Open(view)
		if !ok {
			return emptyMultiHostSearchResult(), fmt.Errorf("%w: case=%q host=%q version=%q", ErrViewNotFound, view.CaseID, view.HostID, view.Version)
		}

		viewResult, err := caseStore.SearchInvestigation(searchOptions)
		if err != nil {
			return emptyMultiHostSearchResult(), fmt.Errorf("search case=%q host=%q version=%q: %w", view.CaseID, view.HostID, view.Version, err)
		}

		result.Total += uint64(viewResult.Total)
		for evidenceType, count := range viewResult.ByType {
			result.ByType[evidenceType] += uint64(count)
		}
		result.ByView = append(result.ByView, InvestigationViewSummary{
			View:   view,
			Total:  viewResult.Total,
			ByType: cloneTypeCounts(viewResult.ByType),
		})
		for _, item := range viewResult.Items {
			result.Items = append(result.Items, InvestigationSearchItem{
				View: view,
				Item: item,
			})
		}
	}

	sort.SliceStable(result.Items, func(leftIndex, rightIndex int) bool {
		left := result.Items[leftIndex].Item.Timestamp
		right := result.Items[rightIndex].Item.Timestamp

		if left.IsZero() && right.IsZero() {
			return false
		}
		if left.IsZero() {
			return false
		}
		if right.IsZero() {
			return true
		}

		return left.After(right)
	})

	if len(result.Items) > limit {
		result.Items = result.Items[:limit]
	}

	return result, nil
}

func validateInvestigationViews(views []View) error {
	seen := make(map[View]struct{}, len(views))
	caseID := ""
	for _, view := range views {
		if !view.Valid() {
			return ErrInvalidView
		}
		if _, duplicate := seen[view]; duplicate {
			return ErrDuplicateView
		}
		seen[view] = struct{}{}

		if caseID == "" {
			caseID = view.CaseID
		} else if view.CaseID != caseID {
			return ErrMixedCases
		}
	}

	return nil
}

func normalizeInvestigationLimit(limit int) int {
	switch {
	case limit <= 0:
		return defaultInvestigationLimit
	case limit > maxInvestigationLimit:
		return maxInvestigationLimit
	default:
		return limit
	}
}

func cloneTypeCounts(counts map[string]uint32) map[string]uint32 {
	clone := make(map[string]uint32, len(counts))
	for evidenceType, count := range counts {
		clone[evidenceType] = count
	}

	return clone
}

func emptyMultiHostSearchResult() MultiHostSearchResult {
	return MultiHostSearchResult{
		ByType: make(map[string]uint64),
		ByView: make([]InvestigationViewSummary, 0),
		Items:  make([]InvestigationSearchItem, 0),
	}
}

var _ store.MultiHostInvestigationStore = (*Investigator)(nil)
