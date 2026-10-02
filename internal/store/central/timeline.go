package central

import (
	"fmt"
	"sort"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type MultiHostTimelineOptions = store.MultiHostTimelineOptions

type MultiHostTimelineEvent = store.MultiHostTimelineEvent

type MultiHostTimelineViewSummary = store.MultiHostTimelineViewSummary

type MultiHostTimelineResult = store.MultiHostTimelineResult

func (i *Investigator) QueryTimeline(
	options MultiHostTimelineOptions,
) (MultiHostTimelineResult, error) {
	offset := options.Query.Page.Offset
	if offset < 0 {
		offset = 0
	}
	limit := normalizeInvestigationLimit(options.Query.Page.Limit)
	result := emptyMultiHostTimelineResult(offset, limit)

	if i == nil || i.repository == nil {
		return result, ErrNilRepository
	}
	if err := validateInvestigationViews(options.Views); err != nil {
		return result, err
	}

	needed := safePageEnd(offset, limit)
	for _, view := range options.Views {
		caseStore, ok := i.repository.Open(view)
		if !ok {
			return emptyMultiHostTimelineResult(offset, limit), fmt.Errorf("%w: case=%q host=%q version=%q", ErrViewNotFound, view.CaseID, view.HostID, view.Version)
		}

		viewEvents, viewResult, err := readTimelinePrefix(caseStore, options.Query, needed)
		if err != nil {
			return emptyMultiHostTimelineResult(offset, limit), fmt.Errorf("timeline case=%q host=%q version=%q: %w", view.CaseID, view.HostID, view.Version, err)
		}

		result.Total += uint64(viewResult.Total)
		for category, count := range viewResult.CategoryCounts {
			result.CategoryCounts[category] += uint64(count)
		}
		result.ByView = append(result.ByView, MultiHostTimelineViewSummary{
			View:           view,
			Total:          viewResult.Total,
			CategoryCounts: cloneCategoryCounts(viewResult.CategoryCounts),
		})
		for _, event := range viewEvents {
			result.Events = append(result.Events, MultiHostTimelineEvent{
				View:  view,
				Event: event,
			})
		}
	}

	sort.SliceStable(result.Events, func(leftIndex, rightIndex int) bool {
		left := result.Events[leftIndex].Event.Timestamp
		right := result.Events[rightIndex].Event.Timestamp

		if left.IsZero() && right.IsZero() {
			return false
		}
		if left.IsZero() {
			return false
		}
		if right.IsZero() {
			return true
		}
		if options.Query.Order == "desc" {
			return left.After(right)
		}

		return left.Before(right)
	})

	start := offset
	if start > len(result.Events) {
		start = len(result.Events)
	}
	end := safePageEnd(start, limit)
	if end > len(result.Events) {
		end = len(result.Events)
	}
	result.Events = append([]MultiHostTimelineEvent(nil), result.Events[start:end]...)
	result.Page.Offset = start
	result.Page.HasMore = uint64(end) < result.Total

	return result, nil
}

func readTimelinePrefix(
	caseStore store.CaseStore,
	options store.TimelineQueryOptions,
	needed int,
) ([]model.TimelineEvent, store.TimelineQueryResult, error) {
	events := make([]model.TimelineEvent, 0)
	var summary store.TimelineQueryResult
	nextOffset := 0

	for len(events) < needed {
		batchLimit := needed - len(events)
		if batchLimit > maxInvestigationLimit {
			batchLimit = maxInvestigationLimit
		}
		query := options
		query.Page = store.QueryPageOptions{Offset: nextOffset, Limit: batchLimit}

		page, err := caseStore.QueryTimeline(query)
		if err != nil {
			return nil, store.TimelineQueryResult{}, err
		}
		if nextOffset == 0 {
			summary.Total = page.Total
			summary.CategoryCounts = cloneCategoryCounts(page.CategoryCounts)
		}
		events = append(events, page.Events...)

		if !page.Page.HasMore || len(page.Events) == 0 {
			break
		}
		nextOffset = page.Page.Offset + len(page.Events)
	}

	return events, summary, nil
}

func safePageEnd(offset int, limit int) int {
	maxInt := int(^uint(0) >> 1)
	if offset > maxInt-limit {
		return maxInt
	}

	return offset + limit
}

func cloneCategoryCounts(counts map[string]uint32) map[string]uint32 {
	clone := make(map[string]uint32, len(counts))
	for category, count := range counts {
		clone[category] = count
	}

	return clone
}

func emptyMultiHostTimelineResult(offset int, limit int) MultiHostTimelineResult {
	return MultiHostTimelineResult{
		Page: store.QueryPageResult{
			Offset: offset,
			Limit:  limit,
		},
		CategoryCounts: make(map[string]uint64),
		ByView:         make([]MultiHostTimelineViewSummary, 0),
		Events:         make([]MultiHostTimelineEvent, 0),
	}
}
