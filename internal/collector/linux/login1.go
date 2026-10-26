package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"ir-toolkit/internal/model"
)

const login1Address = "unix:path=/run/dbus/system_bus_socket"
const login1Interface = "org.freedesktop.login1.Session"
const login1SessionLimit = 64
const login1ReplyLimit = 256 << 10
const login1TotalLimit = 4 << 20

type login1Run func(context.Context, []string, int) ([]byte, []byte, error)

var login1OwnerPattern = regexp.MustCompile(`^:[0-9]+\.[0-9]+$`)
var login1BusPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var login1PathPattern = regexp.MustCompile(`^/org/freedesktop/login1/session/[A-Za-z0-9_]+$`)

func login1Envelope(content []byte, signature string) (json.RawMessage, error) {
	if len(content) > login1ReplyLimit {
		return nil, fmt.Errorf("login1 response exceeds limit")
	}
	var reply struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	d := json.NewDecoder(bytes.NewReader(content))
	d.DisallowUnknownFields()
	if err := d.Decode(&reply); err != nil {
		return nil, err
	}
	if d.Decode(new(any)) != io.EOF || reply.Type != signature || len(reply.Data) != 1 {
		return nil, fmt.Errorf("unexpected busctl response envelope/signature")
	}
	return reply.Data[0], nil
}

func login1Sessions(content []byte) ([]model.LinuxLogin1Session, error) {
	data, err := login1Envelope(content, "a(susso)")
	if err != nil {
		return nil, err
	}
	var rows [][]json.RawMessage
	if err := json.Unmarshal(data, &rows); err != nil || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("invalid login1 session array")
	}
	items := make([]model.LinuxLogin1Session, 0, min(len(rows), login1SessionLimit))
	ids, paths := map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		if len(row) != 5 {
			return nil, fmt.Errorf("invalid login1 session tuple")
		}
		item := model.LinuxLogin1Session{PropertiesCall: -1}
		for index, target := range []any{&item.SessionID, &item.ReportedUID, &item.ReportedUser, &item.ReportedSeat, &item.ObjectPath} {
			if bytes.Equal(bytes.TrimSpace(row[index]), []byte("null")) {
				return nil, fmt.Errorf("null session field")
			}
			if err := json.Unmarshal(row[index], target); err != nil {
				return nil, fmt.Errorf("invalid session field: %w", err)
			}
		}
		if item.SessionID == "" || len(item.SessionID) > 256 || len(item.ReportedUser) > 4096 || len(item.ReportedSeat) > 256 || !login1PathPattern.MatchString(item.ObjectPath) || len(item.ObjectPath) > 512 || ids[item.SessionID] || paths[item.ObjectPath] {
			return nil, fmt.Errorf("invalid or duplicate session identity/path")
		}
		ids[item.SessionID], paths[item.ObjectPath] = true, true
		if len(items) < login1SessionLimit {
			items = append(items, item)
		}
	}
	if len(rows) > login1SessionLimit {
		return items, fmt.Errorf("login1 session limit %d exceeded; properties read only for retained prefix", login1SessionLimit)
	}
	return items, nil
}

// Collect only a fixed read-only call inventory. Owner pinning avoids silently
// switching service owners, but multiple command connections are not atomic.
func collectLogin1(ctx context.Context, run login1Run, bootID, executable, address string) (result model.LinuxLogin1Snapshot, resultErr error) {
	result = model.LinuxLogin1Snapshot{Status: "error", StartedAt: time.Now().UTC(), BootID: bootID, Executable: executable, BusAddress: address, Sessions: []model.LinuxLogin1Session{}, Calls: []model.LinuxLogin1Call{}, Warnings: []string{"Linux login1 scope: live service-reported observations, not atomic, not SSH outcomes, complete session history, process identity or proof of execution. No time-window trimming; raw properties are not interpreted. Absent/empty/unreadable results do not prove absence of activity."}}
	defer func() { result.CompletedAt = time.Now().UTC() }()
	if ctx == nil {
		return result, fmt.Errorf("login1 collection context required")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var failures []error
	remaining := login1TotalLimit
	call := func(destination, path, iface, method string, arguments ...string) ([]byte, int, error) {
		index := len(result.Calls)
		observation := model.LinuxLogin1Call{Destination: destination, ObjectPath: path, Interface: iface, Method: method, Status: "error", StartedAt: time.Now().UTC()}
		callCtx, callCancel := context.WithTimeout(ctx, 2*time.Second)
		defer callCancel()
		args := []string{"--address=" + address, "--auto-start=no", "--allow-interactive-authorization=no", "--timeout=2s", "--json=short", "--no-pager", "call", destination, path, iface, method}
		args = append(args, arguments...)
		limit := min(login1ReplyLimit, remaining)
		var content, stderr []byte
		err := callCtx.Err()
		if err == nil && limit <= 0 {
			err = fmt.Errorf("login1 total response limit exceeded")
		}
		if err == nil {
			content, stderr, err = run(callCtx, args, limit)
		}
		if errors.Is(err, errLogin1OutputLimit) {
			remaining = 0
			content = nil
		}
		if len(content) > limit {
			content = nil
			remaining = 0
			err = errors.Join(err, fmt.Errorf("login1 response limit exceeded"))
		}
		remaining -= len(content)
		if len(stderr) > 8192 {
			stderr = stderr[:8192]
			err = errors.Join(err, fmt.Errorf("login1 diagnostic limit exceeded"))
		}
		observation.Stderr = stderr
		// Retain captured stdout on method/format failure; it may be incomplete
		// on cancellation and is never a successful response. Drop on overflow.
		if len(content) != 0 {
			observation.Content = content
			observation.SHA256 = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		if err == nil {
			observation.Status = "observed"
		} else {
			observation.Error = err.Error()
		}
		observation.CompletedAt = time.Now().UTC()
		result.Calls = append(result.Calls, observation)
		return content, index, err
	}
	mark := func(index int, err error) {
		result.Calls[index].Status = "error"
		result.Calls[index].Error = err.Error()
		failures = append(failures, err)
	}
	readIdentity := func(method string, pattern *regexp.Regexp, arguments ...string) (string, error) {
		content, at, err := call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", method, arguments...)
		var value string
		if err == nil {
			var data json.RawMessage
			data, err = login1Envelope(content, "s")
			if err == nil {
				err = json.Unmarshal(data, &value)
			}
			if err == nil && (len(value) > 256 || !pattern.MatchString(value)) {
				err = fmt.Errorf("invalid bus identity response for %s", method)
			}
		}
		if err != nil {
			mark(at, err)
		}
		return value, err
	}
	var err error
	result.BusID, err = readIdentity("GetId", login1BusPattern)
	if err != nil {
		return result, errors.Join(failures...)
	}
	result.ServiceOwner, err = readIdentity("GetNameOwner", login1OwnerPattern, "s", "org.freedesktop.login1")
	if err != nil {
		return result, errors.Join(failures...)
	}
	content, index, err := call(result.ServiceOwner, "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListSessions")
	if err != nil {
		mark(index, err)
		return result, errors.Join(failures...)
	}
	result.Sessions, err = login1Sessions(content)
	if err != nil {
		mark(index, err)
	}
	if result.Sessions == nil {
		result.Sessions = []model.LinuxLogin1Session{}
		return result, errors.Join(failures...)
	}
	result.Status = "observed_subset"
	for i := range result.Sessions {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		content, at, err := call(result.ServiceOwner, result.Sessions[i].ObjectPath, "org.freedesktop.DBus.Properties", "GetAll", "s", login1Interface)
		result.Sessions[i].PropertiesCall = at
		if err == nil {
			var properties json.RawMessage
			properties, err = login1Envelope(content, "a{sv}")
			// Keep property payload opaque in phase one; do not normalize booleans,
			// missing values, PID, addresses or timestamps into session facts.
			if err == nil && (len(bytes.TrimSpace(properties)) == 0 || bytes.TrimSpace(properties)[0] != '{') {
				err = fmt.Errorf("invalid login1 property dictionary")
			}
		}
		if err != nil {
			mark(at, err)
		}
	}
	ownerAfter, ownerErr := readIdentity("GetNameOwner", login1OwnerPattern, "s", "org.freedesktop.login1")
	busAfter, busErr := readIdentity("GetId", login1BusPattern)
	if ownerErr == nil && ownerAfter != result.ServiceOwner {
		failures = append(failures, fmt.Errorf("login1 service owner changed during observation"))
	}
	if busErr == nil && busAfter != result.BusID {
		failures = append(failures, fmt.Errorf("D-Bus identity changed during observation"))
	}
	if len(failures) != 0 {
		result.Status = "partial"
		result.Warnings = append(result.Warnings, "login1 observations incomplete; inspect per-call errors and unread properties_call=-1 entries.")
	}
	return result, errors.Join(failures...)
}
