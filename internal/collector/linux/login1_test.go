package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func login1TestRun(t *testing.T, change func(string, int, []byte) ([]byte, error)) login1Run {
	t.Helper()
	counts := map[string]int{}
	return func(ctx context.Context, args []string, limit int) ([]byte, []byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded call")
		}
		joined := strings.Join(args, " ")
		for _, flag := range []string{"--auto-start=no", "--allow-interactive-authorization=no", "--timeout=2s", "--json=short", "--no-pager"} {
			if !strings.Contains(joined, flag) {
				t.Fatal("unsafe call", joined)
			}
		}
		method := args[10]
		counts[method]++
		var content string
		switch method {
		case "GetId":
			content = `{"type":"s","data":["0123456789abcdef0123456789abcdef"]}`
		case "GetNameOwner":
			content = `{"type":"s","data":[":1.42"]}`
		case "ListSessions":
			if args[7] != ":1.42" {
				t.Fatal("owner not pinned", args)
			}
			content = `{"type":"a(susso)","data":[[["s1",1000,"Alice","","/org/freedesktop/login1/session/s1"]]]}`
		case "GetAll":
			if args[7] != ":1.42" || args[8] != "/org/freedesktop/login1/session/s1" || args[11] != "s" || args[12] != login1Interface {
				t.Fatal("unsafe property request", args)
			}
			content = `{"type":"a{sv}","data":[{"Active":{"type":"b","data":false},"Leader":{"type":"u","data":42}}]}`
		default:
			t.Fatal("non-read-only call", args)
		}
		out := []byte(content)
		if change != nil {
			var err error
			out, err = change(method, counts[method], out)
			return out, nil, err
		}
		return out, nil, nil
	}
}

func TestLogin1ReadOnlyObservations(t *testing.T) {
	r, err := collectLogin1(context.Background(), login1TestRun(t, nil), "boot-fixture", "/usr/bin/busctl", login1Address)
	if err != nil || r.Status != "observed_subset" || len(r.Sessions) != 1 || len(r.Calls) != 6 || r.ServiceOwner != ":1.42" || r.CompletedAt.Before(r.StartedAt) {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Sessions[0].ReportedUser != "Alice" || r.Sessions[0].PropertiesCall != 3 {
		t.Fatal(r.Sessions)
	}
	for _, call := range r.Calls {
		if call.Status != "observed" || call.SHA256 != fmt.Sprintf("%x", sha256.Sum256(call.Content)) || call.CompletedAt.Before(call.StartedAt) {
			t.Fatal(call)
		}
	}
	if !bytes.Contains(r.Calls[3].Content, []byte(`"data":false`)) {
		t.Fatal("raw false lost")
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"logon_id"`)) {
		t.Fatal("invented Windows identity")
	}
}

func TestLogin1PartialErrorsAndIdentityChanges(t *testing.T) {
	for _, test := range []struct {
		name, method string
		count        int
		response     string
		failure      error
		status       string
	}{
		{"unavailable", "GetId", 1, "", errors.New("bus unavailable"), "error"},
		{"no owner", "GetNameOwner", 1, "", errors.New("NameHasNoOwner"), "error"},
		{"bad owner", "GetNameOwner", 1, `{"type":"s","data":["org.freedesktop.login1"]}`, nil, "error"},
		{"session vanished", "GetAll", 1, "", errors.New("UnknownObject"), "partial"},
		{"wrong properties", "GetAll", 1, `{"type":"a{sv}","data":[[]]}`, nil, "partial"},
		{"owner changed", "GetNameOwner", 2, `{"type":"s","data":[":1.43"]}`, nil, "partial"},
		{"bus changed", "GetId", 2, `{"type":"s","data":["abcdef0123456789abcdef0123456789"]}`, nil, "partial"},
		{"output overflow", "GetAll", 1, "", errLogin1OutputLimit, "partial"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, err := collectLogin1(context.Background(), login1TestRun(t, func(method string, count int, original []byte) ([]byte, error) {
				if method == test.method && count == test.count {
					return []byte(test.response), test.failure
				}
				return original, nil
			}), "boot", "busctl", login1Address)
			if err == nil || r.Status != test.status {
				t.Fatalf("%+v %v", r, err)
			}
			if test.failure != nil && !errors.Is(err, test.failure) {
				t.Fatal("lost error identity", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err := collectLogin1(ctx, func(context.Context, []string, int) ([]byte, []byte, error) {
		t.Fatal("cancelled context invoked transport")
		return nil, nil, nil
	}, "", "", login1Address)
	if !errors.Is(err, context.Canceled) || r.Status != "error" {
		t.Fatal(r, err)
	}
	if _, err := collectLogin1(nil, nil, "", "", login1Address); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestLogin1StrictListAndLimits(t *testing.T) {
	for _, data := range []string{
		`{"type":"a(susso)","data":[null]}`,
		`{"type":"a(susso)","data":[[["s1",-1,"u","","/org/freedesktop/login1/session/s1"]]]}`,
		`{"type":"a(susso)","data":[[["s1",0,null,"","/org/freedesktop/login1/session/s1"]]]}`,
		`{"type":"a(susso)","data":[[["s1",0,"u","","/untrusted/path"]]]}`,
		`{"type":"a(susso)","data":[[["s1",0,"u","","/org/freedesktop/login1/session/s1"],["s1",0,"u","","/org/freedesktop/login1/session/s2"]]]}`,
		`{"type":"s","data":["wrong signature"]}`,
		`{"type":"a(susso)","data":[[]]} {}`,
	} {
		if _, err := login1Sessions([]byte(data)); err == nil {
			t.Fatal("ambiguous list accepted", data)
		}
	}
	rows := []any{}
	for i := 0; i < 65; i++ {
		rows = append(rows, []any{fmt.Sprint(i), uint32(i), "u", "", fmt.Sprintf("/org/freedesktop/login1/session/s%d", i)})
	}
	data, _ := json.Marshal(map[string]any{"type": "a(susso)", "data": []any{rows}})
	items, err := login1Sessions(data)
	if err == nil || len(items) != 64 || items[63].PropertiesCall != -1 {
		t.Fatal(len(items), err)
	}
	if _, err := login1Envelope(bytes.Repeat([]byte("x"), login1ReplyLimit+1), "s"); err == nil {
		t.Fatal("reply overflow accepted")
	}
	capture := &login1Capture{maximum: 3}
	if n, err := capture.Write([]byte("12345")); n != 5 || err != nil || !capture.overflow || string(capture.content) != "123" {
		t.Fatal(capture, n, err)
	}
	if n, _ := capture.Write([]byte("more")); n != 4 || string(capture.content) != "123" {
		t.Fatal("capture grew")
	}
}

func TestLogin1DeadlinePropagation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := collectLogin1(ctx, func(ctx context.Context, _ []string, _ int) ([]byte, []byte, error) {
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}, "", "", login1Address)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestLogin1TotalResponseBudget(t *testing.T) {
	rows := []any{}
	for i := 0; i < 64; i++ {
		rows = append(rows, []any{fmt.Sprint(i), i, "user", "", fmt.Sprintf("/org/freedesktop/login1/session/s%d", i)})
	}
	list, _ := json.Marshal(map[string]any{"type": "a(susso)", "data": []any{rows}})
	property := append([]byte(`{"type":"a{sv}","data":[{}]}`), bytes.Repeat([]byte(" "), 200000)...)
	invocations := 0
	r, err := collectLogin1(context.Background(), func(_ context.Context, args []string, limit int) ([]byte, []byte, error) {
		invocations++
		switch args[10] {
		case "GetId":
			return []byte(`{"type":"s","data":["0123456789abcdef0123456789abcdef"]}`), nil, nil
		case "GetNameOwner":
			return []byte(`{"type":"s","data":[":1.42"]}`), nil, nil
		case "ListSessions":
			return list, nil, nil
		case "GetAll":
			if len(property) > limit {
				return nil, nil, errLogin1OutputLimit
			}
			return property, nil, nil
		}
		t.Fatal(args)
		return nil, nil, nil
	}, "", "", login1Address)
	if err == nil || r.Status != "partial" || len(r.Sessions) != 64 || invocations >= 64 {
		t.Fatal(r.Status, invocations, err)
	}
	stored := 0
	for _, call := range r.Calls {
		stored += len(call.Content)
		if len(call.Content) > login1ReplyLimit {
			t.Fatal("per-call limit exceeded")
		}
	}
	if stored > login1TotalLimit {
		t.Fatal("total stored response limit exceeded", stored)
	}
}

func FuzzLogin1SessionEnvelope(f *testing.F) {
	f.Add([]byte(`{"type":"a(susso)","data":[[["s1",1000,"Alice","","/org/freedesktop/login1/session/s1"]]]}`))
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = login1Sessions(data) })
}
