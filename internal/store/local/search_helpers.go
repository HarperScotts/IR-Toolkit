package local

import (
	"fmt"
	"strings"
)

func (s *CaseStore) ensureSearchDomains(types map[string]bool) error {
	checks := []struct {
		kind string
		load func() error
	}{
		{"process", s.ensureProcesses}, {"login", s.ensureLogin},
		{"network", s.ensureNetwork}, {"historical_process", s.ensureHistoricalProcesses},
		{"powershell", s.ensurePowerShell}, {"windows_event", s.ensureWindowsEvents},
		{"ioc", s.ensureIOC}, {"file", s.ensureFiles}, {"persistence", s.ensurePersistence},
		{"timeline", s.ensureTimeline}, {"correlation", s.ensureCorrelation},
	}
	for _, check := range checks {
		enabled := searchTypeEnabled(types, check.kind)
		if check.kind == "correlation" {
			enabled = searchTypeEnabled(types, "correlation_node") || searchTypeEnabled(types, "correlation_edge")
		}
		if enabled {
			if err := check.load(); err != nil {
				return fmt.Errorf("search %s: %w", check.kind, err)
			}
		}
	}
	return nil
}

func searchContains(
	query string,
	values ...string,
) bool {

	query =
		strings.ToLower(
			strings.TrimSpace(
				query,
			),
		)

	if query == "" {
		return false
	}

	for _, value := range values {

		if strings.Contains(
			strings.ToLower(
				value,
			),
			query,
		) {

			return true
		}
	}

	return false
}

func searchTypeEnabled(
	types map[string]bool,
	value string,
) bool {

	if len(types) == 0 {
		return true
	}

	return types[strings.ToLower(
		value)]
}
