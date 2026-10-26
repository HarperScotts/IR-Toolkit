package analyzer

import (
	"context"
	"strings"
	"testing"

	"ir-toolkit/internal/model"
)

func TestNetworkProcessInstanceMatching(t *testing.T) {
	for _, test := range []struct {
		name, processID, connectionID string
		pid                           uint32
		want                          bool
	}{
		{"matching Linux instance", "linux-proc:42:100", "linux-proc:42:100", 42, true},
		{"PID reused", "linux-proc:42:100", "linux-proc:42:200", 42, false},
		{"process identity unknown", "", "linux-proc:42:100", 42, false},
		{"connection identity unknown", "linux-proc:42:100", "", 42, false},
		{"legacy Windows unchanged", "", "", 42, true},
		{"zero PID is unowned", "", "", 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			process := model.Process{PID: test.pid, Name: "example", ProcessInstanceID: test.processID}
			connection := model.NetworkConnection{PID: test.pid, ProcessInstanceID: test.connectionID, Protocol: "TCP", LocalAddress: "127.0.0.1", LocalPort: 123, RemoteAddress: "10.0.0.2", RemotePort: 443, State: "ESTABLISHED"}
			got := NewProcessNetworkAnalyzer().Analyze(context.Background(), []model.Process{process}, []model.NetworkConnection{connection})
			if (len(got.Processes[0].Connections) == 1) != test.want || (len(got.OrphanConnections) == 1) == test.want {
				t.Fatalf("instance mismatch linked: %+v", got)
			}
			if !test.want && got.OrphanConnections[0] != connection {
				t.Fatal("unowned raw connection changed")
			}
		})
	}
}

func TestLinuxReportDoesNotInferWindowsAuditStatus(t *testing.T) {
	var report model.CaseReport
	appendEvidenceGaps(&report, model.AuditCapabilitySnapshot{Warnings: []string{"Linux capability unassessed"}}, "linux")
	text := strings.Join(report.EvidenceGaps, " ")
	if !strings.Contains(text, "Linux capability unassessed") || strings.Contains(text, "was disabled") || strings.Contains(text, "Security event log was unavailable") {
		t.Fatal("Windows audit assumptions leaked", text)
	}
	report = model.CaseReport{}
	appendEvidenceGaps(&report, model.AuditCapabilitySnapshot{}, "windows")
	if !strings.Contains(strings.Join(report.EvidenceGaps, " "), "Windows Security event log was unavailable") {
		t.Fatal("Windows gaps changed")
	}
}

func TestConnectedUDPIsNotAListener(t *testing.T) {
	for _, test := range []struct {
		remote             string
		port               uint32
		listener, external bool
	}{
		{"", 0, true, false}, {"0.0.0.0", 0, true, false}, {"::", 0, true, false},
		{"8.8.8.8", 53, false, true}, {"127.0.0.1", 53, false, false}, {"10.0.0.2", 53, false, false},
	} {
		connection := model.NetworkConnection{PID: 42, Protocol: "UDP", LocalAddress: "0.0.0.0", LocalPort: 50000, RemoteAddress: test.remote, RemotePort: test.port}
		result := NewProcessNetworkAnalyzer().Analyze(context.Background(), []model.Process{{PID: 42}}, []model.NetworkConnection{connection})
		if (len(result.Processes[0].Listeners) == 1) != test.listener || (len(result.Processes[0].ExternalConnections) == 1) != test.external {
			t.Fatalf("UDP peer classification changed: %+v", result)
		}
	}
}
