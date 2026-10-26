// Package testutil provides deterministic synthetic evidence for contract tests.
// It is not imported by production collection, analysis or serving code.
package testutil

import (
	"crypto/sha256"
	"fmt"
	"time"

	"ir-toolkit/internal/model"
)

func Login1Snapshot() model.LinuxLogin1Snapshot {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	s := model.LinuxLogin1Snapshot{Status: "observed_subset", StartedAt: start, CompletedAt: start.Add(time.Second), BootID: "fixture-boot", BusID: "0123456789abcdef0123456789abcdef", ServiceOwner: ":1.42", Warnings: []string{"Synthetic login1 evidence; not real logind acceptance."}}
	call := func(destination, path, iface, method, content string) model.LinuxLogin1Call {
		return model.LinuxLogin1Call{Destination: destination, ObjectPath: path, Interface: iface, Method: method, Status: "observed", StartedAt: start, CompletedAt: start.Add(time.Millisecond), Content: []byte(content), SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content)))}
	}
	bus := func(method, reply string) model.LinuxLogin1Call {
		return call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", method, reply)
	}
	getID := bus("GetId", `{"type":"s","data":["0123456789abcdef0123456789abcdef"]}`)
	owner := bus("GetNameOwner", `{"type":"s","data":[":1.42"]}`)
	s.Calls = []model.LinuxLogin1Call{getID, owner, call(s.ServiceOwner, "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "ListSessions", `{"type":"a(susso)","data":[[["s1",0,"Alice","","/org/freedesktop/login1/session/s1"],["s2",1000,"alice","seat0","/org/freedesktop/login1/session/s2"]]]}`),
		call(s.ServiceOwner, "/org/freedesktop/login1/session/s1", "org.freedesktop.DBus.Properties", "GetAll", `{"type":"a{sv}","data":[{"Id":{"type":"s","data":"s1"},"Active":{"type":"b","data":false},"Remote":{"type":"b","data":false},"Leader":{"type":"u","data":0},"State":{"type":"s","data":"online"},"TTY":{"type":"s","data":""},"Timestamp":{"type":"t","data":18446744073709551615},"FutureProperty":{"type":"s","data":"<script>literal</script>"}}]}`),
		call(s.ServiceOwner, "/org/freedesktop/login1/session/s2", "org.freedesktop.DBus.Properties", "GetAll", `{"type":"a{sv}","data":[{}]}`), owner, getID}
	s.Sessions = []model.LinuxLogin1Session{{SessionID: "s1", ReportedUID: 0, ReportedUser: "Alice", ObjectPath: "/org/freedesktop/login1/session/s1", PropertiesCall: 3}, {SessionID: "s2", ReportedUID: 1000, ReportedUser: "alice", ReportedSeat: "seat0", ObjectPath: "/org/freedesktop/login1/session/s2", PropertiesCall: 4}}
	return s
}

func Login1SetContent(call *model.LinuxLogin1Call, content string) {
	call.Content = []byte(content)
	call.SHA256 = fmt.Sprintf("%x", sha256.Sum256(call.Content))
}
