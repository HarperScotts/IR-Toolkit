package analyzer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"ir-toolkit/internal/model"
)

const login1Profile = "login1-observation-v1"

// Reject duplicate keys rather than silently accepting a different identity or
// boolean value. All parsing is bounded by the source/call limits below.
func login1Object(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("expected JSON object")
	}
	result := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, fmt.Errorf("invalid object key")
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate JSON key %q", name)
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		result[name] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	return result, nil
}

func login1Data(call model.LinuxLogin1Call, signature string) (json.RawMessage, error) {
	if call.Status != "observed" || call.Error != "" || len(call.Content) == 0 || len(call.Content) > 256<<10 || !utf8.Valid(call.Content) || call.SHA256 != fmt.Sprintf("%x", sha256.Sum256(call.Content)) {
		return nil, fmt.Errorf("incomplete call or invalid source hash")
	}
	envelope, err := login1Object(call.Content)
	if err != nil {
		return nil, err
	}
	var kind string
	var data []json.RawMessage
	if len(envelope) != 2 || json.Unmarshal(envelope["type"], &kind) != nil || kind != signature || json.Unmarshal(envelope["data"], &data) != nil || len(data) != 1 {
		return nil, fmt.Errorf("invalid response envelope/signature")
	}
	return data[0], nil
}

func login1NormalizeProperties(data []byte, sessionID string) (model.LinuxLogin1Properties, []string) {
	var result model.LinuxLogin1Properties
	properties, err := login1Object(data)
	if err != nil {
		return result, []string{err.Error()}
	}
	warnings := []string{}
	read := func(name, signature string, target any) {
		raw, exists := properties[name]
		if !exists {
			return
		}
		value, err := login1Object(raw)
		var kind string
		temporary := reflect.New(reflect.TypeOf(target).Elem())
		if err != nil || len(value) != 2 || json.Unmarshal(value["type"], &kind) != nil || kind != signature || bytes.Equal(bytes.TrimSpace(value["data"]), []byte("null")) || json.Unmarshal(value["data"], temporary.Interface()) != nil {
			warnings = append(warnings, "Invalid typed property: "+name)
			return
		}
		reflect.ValueOf(target).Elem().Set(temporary.Elem())
	}
	// Id is optional for old/partial dictionaries, but an explicit mismatch
	// blocks all normalized properties rather than attaching them arbitrarily.
	var id *string
	read("Id", "s", &id)
	if _, exists := properties["Id"]; exists && id == nil {
		return result, warnings
	}
	if id != nil && *id != sessionID {
		return result, []string{"Property Id disagrees with listed session; normalized properties withheld."}
	}
	read("State", "s", &result.State)
	read("Active", "b", &result.Active)
	read("Remote", "b", &result.Remote)
	read("Leader", "u", &result.Leader)
	read("Type", "s", &result.Type)
	read("Class", "s", &result.Class)
	read("TTY", "s", &result.TTY)
	read("Service", "s", &result.Service)
	read("RemoteHost", "s", &result.RemoteHost)
	read("RemoteUser", "s", &result.RemoteUser)
	read("Timestamp", "t", &result.TimestampUS)
	return result, warnings
}

var login1AnalysisPath = regexp.MustCompile(`^/org/freedesktop/login1/session/[A-Za-z0-9_]+$`)
var login1AnalysisOwner = regexp.MustCompile(`^:[0-9]+\.[0-9]+$`)
var login1AnalysisBus = regexp.MustCompile(`^[0-9a-f]{32}$`)

func analyzeLogin1(ctx context.Context, source *model.LinuxLogin1Snapshot) *model.LinuxLogin1Analysis {
	if source == nil {
		return nil
	}
	result := &model.LinuxLogin1Analysis{Profile: login1Profile, Status: "skipped", SourceStatus: source.Status, StartedAt: source.StartedAt, CompletedAt: source.CompletedAt, BootID: source.BootID, BusID: source.BusID, ServiceOwner: source.ServiceOwner, Observations: []model.LinuxLogin1Observation{}, Warnings: []string{"Linux login1 analysis: service-reported observations, not verified activity, SSH authentication outcomes, historical sessions or process identities. Active is a reported foreground hint; missing values remain unknown. No time-window filtering, findings, graph edges or Timeline events."}}
	fail := func(message string) *model.LinuxLogin1Analysis {
		result.Warnings = append(result.Warnings, message)
		return result
	}
	if ctx == nil {
		return fail("login1 analysis requires context")
	}
	if len(source.Warnings) > 128 {
		return fail("login1 source warning limit exceeded.")
	}
	for _, warning := range source.Warnings {
		if len(warning) > 4096 {
			return fail("login1 source warning size limit exceeded.")
		}
	}
	result.Warnings = append(result.Warnings, source.Warnings...)
	if source.Status != "observed_subset" && source.Status != "partial" {
		return fail("login1 source unavailable/incomplete; no normalized observations.")
	}
	if len(source.Calls) > 69 || len(source.Sessions) > 64 || !login1AnalysisOwner.MatchString(source.ServiceOwner) || !login1AnalysisBus.MatchString(source.BusID) || source.StartedAt.IsZero() || source.CompletedAt.Before(source.StartedAt) {
		return fail("Invalid login1 source scope, time range or limits.")
	}
	var list *model.LinuxLogin1Call
	total := 0
	for at := range source.Calls {
		call := &source.Calls[at]
		total += len(call.Content)
		if len(call.Content) > 256<<10 || len(call.Stderr) > 8192 || total > 4<<20 {
			return fail("login1 input exceeds analysis limits.")
		}
		if call.Method == "ListSessions" {
			if list != nil || call.Destination != source.ServiceOwner || call.ObjectPath != "/org/freedesktop/login1" || call.Interface != "org.freedesktop.login1.Manager" {
				return fail("Ambiguous/mismatched login1 session list call.")
			}
			list = call
		}
	}
	if list == nil {
		return fail("No login1 session list response.")
	}
	// A limit-marked list may have complete bytes but error status. Do not
	// reinterpret that special error as a successful source in this profile.
	data, err := login1Data(*list, "a(susso)")
	if err != nil {
		return fail("Invalid login1 list: " + err.Error())
	}
	var rows [][]json.RawMessage
	if json.Unmarshal(data, &rows) != nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) || len(rows) > 64 || len(rows) != len(source.Sessions) {
		return fail("Invalid login1 list shape/count; source retained, normalization withheld.")
	}
	seenID, seenPath := map[string]bool{}, map[string]bool{}
	for at, row := range rows {
		if len(row) != 5 {
			return fail("Invalid login1 tuple.")
		}
		var id, user, seat, path string
		var uid uint32
		for i, target := range []any{&id, &uid, &user, &seat, &path} {
			if bytes.Equal(bytes.TrimSpace(row[i]), []byte("null")) || json.Unmarshal(row[i], target) != nil {
				return fail("Invalid login1 list field.")
			}
		}
		session := source.Sessions[at]
		if id == "" || len(id) > 256 || len(user) > 4096 || len(seat) > 256 || len(path) > 512 || !login1AnalysisPath.MatchString(path) || seenID[id] || seenPath[path] || session.SessionID != id || session.ReportedUID != uid || session.ReportedUser != user || session.ReportedSeat != seat || session.ObjectPath != path {
			return fail("Ambiguous or mismatched login1 list identity.")
		}
		seenID[id], seenPath[path] = true, true
	}
	result.ListSHA256 = list.SHA256
	result.Status = "observed_subset"
	if source.Status == "partial" {
		result.Status = "partial"
		result.Warnings = append(result.Warnings, "Source was partial; normalized values remain conditional source claims.")
	}
	for _, session := range source.Sessions {
		if err := ctx.Err(); err != nil {
			result.Status = "partial"
			result.Warnings = append(result.Warnings, err.Error())
			break
		}
		item := model.LinuxLogin1Observation{Session: session, PropertyStatus: "unavailable", Warnings: []string{}}
		propertySHA := "unread"
		if session.PropertiesCall >= 0 && session.PropertiesCall < len(source.Calls) {
			call := source.Calls[session.PropertiesCall]
			item.SourceCall = &call
			propertySHA = call.SHA256
			if call.Destination != source.ServiceOwner || call.ObjectPath != session.ObjectPath || call.Interface != "org.freedesktop.DBus.Properties" || call.Method != "GetAll" {
				item.Warnings = append(item.Warnings, "Mismatched property call reference; properties withheld.")
			} else {
				data, err := login1Data(call, "a{sv}")
				if err != nil {
					item.Warnings = append(item.Warnings, "Properties unavailable: "+err.Error())
				} else {
					item.Properties, item.Warnings = login1NormalizeProperties(data, session.SessionID)
					item.PropertyStatus = "observed_subset"
					if len(item.Warnings) > 0 {
						item.PropertyStatus = "partial"
					}
				}
			}
		} else {
			item.Warnings = append(item.Warnings, "Properties were not read or reference is invalid.")
		}
		if item.PropertyStatus != "observed_subset" {
			result.Status = "partial"
		}
		identity := strings.Join([]string{source.BootID, source.BusID, source.ServiceOwner, source.StartedAt.UTC().Format(time.RFC3339Nano), session.ObjectPath, list.SHA256, propertySHA}, "\x00")
		item.ID = fmt.Sprintf("linux-login1:%x", sha256.Sum256([]byte(identity)))
		result.Observations = append(result.Observations, item)
	}
	if result.Status == "partial" {
		result.Warnings = append(result.Warnings, "login1 normalization is partial; inspect per-observation diagnostics.")
	}
	return result
}
