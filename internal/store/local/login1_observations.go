package local

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

func (s *CaseStore) login1Observations() ([]model.LinuxLogin1Observation, error) {
	if err := s.ensureLogin(); err != nil {
		return nil, err
	}
	analysis := s.loginAnalysis.LinuxLogin1
	if analysis == nil {
		return []model.LinuxLogin1Observation{}, nil
	}
	if analysis.Profile != "login1-observation-v1" || len(analysis.Observations) > 64 {
		return nil, fmt.Errorf("unsupported login1 analysis profile/limits")
	}
	seen := map[string]bool{}
	for _, item := range analysis.Observations {
		id := strings.TrimPrefix(item.ID, "linux-login1:")
		if len(id) != 64 || id == item.ID || seen[item.ID] {
			return nil, fmt.Errorf("invalid/duplicate login1 evidence ID")
		}
		if _, err := hex.DecodeString(id); err != nil {
			return nil, fmt.Errorf("invalid login1 evidence ID: %w", err)
		}
		seen[item.ID] = true
	}
	return analysis.Observations, nil
}

func (s *CaseStore) QueryLinuxLogin1(options store.LinuxLogin1QueryOptions) (store.QueryResult[model.LinuxLogin1Observation], error) {
	records, err := s.login1Observations()
	if err != nil {
		return store.QueryResult[model.LinuxLogin1Observation]{}, err
	}
	items := []model.LinuxLogin1Observation{}
	for _, item := range records {
		if options.User != "" && !strings.Contains(item.Session.ReportedUser, options.User) {
			continue
		}
		if options.State != "" && (item.Properties.State == nil || *item.Properties.State != options.State) {
			continue
		}
		if options.Active != nil && (item.Properties.Active == nil || *item.Properties.Active != *options.Active) {
			continue
		}
		if options.Query != "" && !searchContains(options.Query, item.Session.SessionID, item.Session.ReportedUser, item.Session.ObjectPath, item.Session.ReportedSeat) {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	page := normalizeQueryPage(options.Page.Offset, options.Page.Limit, len(items))
	end := queryPageEnd(page, len(items))
	return store.QueryResult[model.LinuxLogin1Observation]{Total: uint32(len(items)), Page: buildQueryPageResult(page, end, len(items)), Items: items[page.Offset:end]}, nil
}

func (s *CaseStore) LinuxLogin1ByID(id string) (model.LinuxLogin1Observation, bool, error) {
	items, err := s.login1Observations()
	if err != nil {
		return model.LinuxLogin1Observation{}, false, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return model.LinuxLogin1Observation{}, false, nil
}
