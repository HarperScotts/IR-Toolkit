package local

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

func (s *CaseStore) linuxLoginIndex() (map[string]int, error) {
	if err := s.ensureLogin(); err != nil {
		return nil, err
	}
	index := map[string]int{}
	for at, record := range s.loginAnalysis.LinuxRecords {
		hexID := strings.TrimPrefix(record.ID, "linux-login:")
		if len(hexID) != 64 || hexID == record.ID {
			return nil, fmt.Errorf("invalid Linux login record ID")
		}
		if _, err := hex.DecodeString(hexID); err != nil {
			return nil, fmt.Errorf("invalid Linux login record ID: %w", err)
		}
		if _, exists := index[record.ID]; exists {
			return nil, fmt.Errorf("duplicate Linux login record ID")
		}
		index[record.ID] = at
	}
	return index, nil
}

func (s *CaseStore) QueryLinuxLogins(options store.LinuxLoginQueryOptions) (store.QueryResult[model.LinuxLoginRecord], error) {
	if !options.Since.IsZero() && !options.Until.IsZero() && options.Since.After(options.Until) {
		return store.QueryResult[model.LinuxLoginRecord]{}, fmt.Errorf("since must not be after until")
	}
	switch options.UnknownTime {
	case "", "include", "exclude", "only":
	default:
		return store.QueryResult[model.LinuxLoginRecord]{}, fmt.Errorf("invalid unknown-time policy")
	}
	if options.IP != "" {
		address, err := netip.ParseAddr(options.IP)
		if err != nil {
			return store.QueryResult[model.LinuxLoginRecord]{}, fmt.Errorf("invalid literal Linux login peer IP: %w", err)
		}
		options.IP = address.String()
	}
	if _, err := s.linuxLoginIndex(); err != nil {
		return store.QueryResult[model.LinuxLoginRecord]{}, err
	}
	items := []model.LinuxLoginRecord{}
	for _, record := range s.loginAnalysis.LinuxRecords {
		if record.Timestamp.IsZero() {
			if options.UnknownTime == "exclude" {
				continue
			}
		} else {
			if options.UnknownTime == "only" || (!options.Since.IsZero() && record.Timestamp.Before(options.Since)) || (!options.Until.IsZero() && record.Timestamp.After(options.Until)) {
				continue
			}
		}
		if options.User != "" && !strings.Contains(record.User, options.User) {
			continue
		} // Linux names retain case.
		if options.IP != "" && record.SourceIP != options.IP {
			continue
		}
		if options.Outcome != "" && record.Outcome != options.Outcome {
			continue
		}
		if options.Query != "" && !searchContains(options.Query, record.RawLine, record.SourcePath, record.User, record.SourceIP, record.Method) {
			continue
		}
		items = append(items, record)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Timestamp.IsZero() != b.Timestamp.IsZero() {
			return !a.Timestamp.IsZero()
		}
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.After(b.Timestamp)
		}
		return a.ID < b.ID
	})
	page := normalizeQueryPage(options.Page.Offset, options.Page.Limit, len(items))
	end := queryPageEnd(page, len(items))
	return store.QueryResult[model.LinuxLoginRecord]{Total: uint32(len(items)), Page: buildQueryPageResult(page, end, len(items)), Items: items[page.Offset:end]}, nil
}

func (s *CaseStore) LinuxLoginRecordByID(id string) (model.LinuxLoginRecord, bool, error) {
	index, err := s.linuxLoginIndex()
	if err != nil {
		return model.LinuxLoginRecord{}, false, err
	}
	at, found := index[id]
	if !found {
		return model.LinuxLoginRecord{}, false, nil
	}
	return s.loginAnalysis.LinuxRecords[at], true, nil
}
