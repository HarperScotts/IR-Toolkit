package web

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"ir-toolkit/internal/store"
)

func (s *Server) handleLinuxLogins(writer http.ResponseWriter, request *http.Request) {
	values := request.URL.Query()
	var since, until time.Time
	for key, target := range map[string]*time.Time{"since": &since, "until": &until} {
		if value := values.Get(key); value != "" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.IsZero() {
				writeAPIError(writer, http.StatusBadRequest, key+" must be a nonzero RFC3339 timestamp with offset")
				return
			}
			*target = parsed
		}
	}
	unknown := values.Get("unknown_time")
	if (!since.IsZero() && !until.IsZero() && since.After(until)) || (unknown != "" && unknown != "include" && unknown != "exclude" && unknown != "only") {
		writeAPIError(writer, http.StatusBadRequest, "invalid time range or unknown_time policy")
		return
	}
	if values.Get("ip") != "" {
		if _, err := netip.ParseAddr(values.Get("ip")); err != nil {
			writeAPIError(writer, http.StatusBadRequest, "ip must be a literal address")
			return
		}
	}
	outcome := values.Get("outcome")
	if outcome != "" && outcome != "accepted" && outcome != "failed" {
		writeAPIError(writer, http.StatusBadRequest, "outcome must be accepted or failed")
		return
	}
	offset, limit := parseQueryPagination(values)
	result, err := s.store.QueryLinuxLogins(store.LinuxLoginQueryOptions{Since: since, Until: until, UnknownTime: unknown, Query: values.Get("q"), User: values.Get("user"), IP: values.Get("ip"), Outcome: outcome, Page: store.QueryPageOptions{Offset: offset, Limit: limit}})
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "query Linux login evidence: "+err.Error())
		return
	}
	analysis, err := s.store.LoginAnalysis()
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "load Linux login coverage: "+err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"total": result.Total, "offset": result.Page.Offset, "limit": result.Page.Limit, "has_more": result.Page.HasMore, "records": result.Items, "sources": analysis.LinuxSources, "warnings": analysis.Warnings, "scope": "Log-reported SSH authentication outcomes, not sessions or unique attempts. Inclusive query bounds; unknown times are context, not confirmed within the window. Raw evidence and saved analysis are unchanged. Coverage diagnostics describe the entire saved analysis, not the filtered page."})
}

func (s *Server) handleLinuxLoginDetail(writer http.ResponseWriter, request *http.Request) {
	id := strings.TrimSpace(request.URL.Query().Get("id"))
	if id == "" {
		writeAPIError(writer, http.StatusBadRequest, "id is required")
		return
	}
	record, found, err := s.store.LinuxLoginRecordByID(id)
	if err != nil {
		writeAPIError(writer, http.StatusInternalServerError, "load Linux login record: "+err.Error())
		return
	}
	if !found {
		writeAPIError(writer, http.StatusNotFound, "Linux login record not found")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"record": record, "scope": "source claim only; timestamp may be unknown and reported PID is not a confirmed process identity"})
}
