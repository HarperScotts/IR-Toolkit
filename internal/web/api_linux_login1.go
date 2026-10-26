package web

import (
	"ir-toolkit/internal/model"
	"net/http"
	"strings"

	"ir-toolkit/internal/store"
)

const login1Scope = "Saved login1 service observations, not confirmed activity, SSH outcomes or process identities. Active means reported foreground hint, not authentication or execution. Missing properties are unknown. Collection time is not session creation/activity time. No live reread or time-window filtering."

func login1Coverage(a *model.LinuxLogin1Analysis) any {
	if a == nil {
		return map[string]any{"status": "not_available", "warnings": []string{"No saved login1 analysis; collect/analyze with a supported version. Missing is not an empty verified session list."}}
	}
	return map[string]any{"profile": a.Profile, "status": a.Status, "source_status": a.SourceStatus, "started_at": a.StartedAt, "completed_at": a.CompletedAt, "boot_id": a.BootID, "bus_id": a.BusID, "service_owner": a.ServiceOwner, "list_sha256": a.ListSHA256, "warnings": a.Warnings}
}

func (s *Server) handleLinuxLogin1(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	for _, key := range []string{"since", "until", "last"} {
		if values.Has(key) {
			writeAPIError(writer, 400, "login1 observations do not support activity time-window filtering")
			return
		}
	}
	var active *bool
	if value := values.Get("active"); value != "" {
		if value != "true" && value != "false" {
			writeAPIError(writer, 400, "active must be true or false")
			return
		}
		v := value == "true"
		active = &v
	}
	offset, limit := parseQueryPagination(values)
	result, err := s.store.QueryLinuxLogin1(store.LinuxLogin1QueryOptions{Query: values.Get("q"), User: values.Get("user"), State: values.Get("state"), Active: active, Page: store.QueryPageOptions{Offset: offset, Limit: limit}})
	if err != nil {
		writeAPIError(writer, 500, "query login1 observations: "+err.Error())
		return
	}
	analysis, err := s.store.LoginAnalysis()
	if err != nil {
		writeAPIError(writer, 500, "load login1 coverage: "+err.Error())
		return
	}
	// Avoid serializing every raw property response into the list/coverage panel.
	items := []model.LinuxLogin1Observation{}
	for _, item := range result.Items {
		item.SourceCall = nil
		items = append(items, item)
	}
	writeJSON(writer, 200, map[string]any{"total": result.Total, "offset": result.Page.Offset, "limit": result.Page.Limit, "has_more": result.Page.HasMore, "records": items, "coverage": login1Coverage(analysis.LinuxLogin1), "scope": login1Scope})
}

func (s *Server) handleLinuxLogin1Detail(writer http.ResponseWriter, request *http.Request) {
	id := strings.TrimSpace(request.URL.Query().Get("id"))
	if id == "" {
		writeAPIError(writer, 400, "id is required")
		return
	}
	record, found, err := s.store.LinuxLogin1ByID(id)
	if err != nil {
		writeAPIError(writer, 500, "load login1 observation: "+err.Error())
		return
	}
	if !found {
		writeAPIError(writer, 404, "login1 observation not found")
		return
	}
	analysis, err := s.store.LoginAnalysis()
	if err != nil {
		writeAPIError(writer, 500, "load login1 context: "+err.Error())
		return
	}
	writeJSON(writer, 200, map[string]any{"record": record, "coverage": login1Coverage(analysis.LinuxLogin1), "scope": login1Scope})
}
