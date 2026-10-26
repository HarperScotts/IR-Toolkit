package analyzer

import (
	"context"
	"testing"
	"time"

	"ir-toolkit/internal/model"
)

func TestHistoricalCurrentProcessRequiresInstanceEvidence(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 8, 0, 0, 123456700, time.UTC)
	for _, test := range []struct {
		name   string
		change func(*model.ProcessEvent, *model.Process)
		want   bool
	}{
		{"exact identity", func(*model.ProcessEvent, *model.Process) {}, true},
		{"normalized path", func(e *model.ProcessEvent, p *model.Process) { p.Path = `"c:/tools/APP.exe"` }, true},
		{"same instant different zone", func(e *model.ProcessEvent, p *model.Process) { p.StartTime = stamp.In(time.FixedZone("UTC+8", 8*3600)) }, true},
		{"PID reused same executable", func(e *model.ProcessEvent, p *model.Process) { e.Timestamp = stamp.Add(-time.Hour) }, false},
		{"later event same PID", func(e *model.ProcessEvent, p *model.Process) { e.Timestamp = stamp.Add(time.Hour) }, false},
		{"no fuzzy time tolerance", func(e *model.ProcessEvent, p *model.Process) { e.Timestamp = stamp.Add(time.Nanosecond) }, false},
		{"missing creation time", func(e *model.ProcessEvent, p *model.Process) { p.StartTime = time.Time{} }, false},
		{"missing event time", func(e *model.ProcessEvent, p *model.Process) { e.Timestamp = time.Time{} }, false},
		{"both times unknown", func(e *model.ProcessEvent, p *model.Process) { e.Timestamp = time.Time{}; p.StartTime = time.Time{} }, false},
		{"missing current path", func(e *model.ProcessEvent, p *model.Process) { p.Path = "" }, false},
		{"missing event path", func(e *model.ProcessEvent, p *model.Process) { e.NewProcessName = "" }, false},
		{"both paths unknown", func(e *model.ProcessEvent, p *model.Process) { e.NewProcessName = " "; p.Path = "" }, false},
		{"different executable", func(e *model.ProcessEvent, p *model.Process) { p.Path = `C:\Tools\other.exe` }, false},
		{"different PID", func(e *model.ProcessEvent, p *model.Process) { p.PID = 43 }, false},
		{"zero PID", func(e *model.ProcessEvent, p *model.Process) { p.PID = 0; e.NewProcessID = 0 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := model.ProcessEvent{EventID: 4688, Timestamp: stamp, NewProcessID: 42, NewProcessName: `C:\Tools\app.exe`, SubjectLogonID: "0xabc"}
			current := model.Process{PID: 42, Path: `C:\Tools\app.exe`, StartTime: stamp}
			test.change(&event, &current)
			result := AnalyzeProcessHistory(context.Background(), model.ProcessEventSnapshot{Events: []model.ProcessEvent{event}}, model.LoginAnalysis{Sessions: []model.LoginSessionAnalysis{{LogonID: "0xabc"}}}, []model.Process{current})
			if len(result.Processes) != 1 {
				t.Fatalf("history lost: %+v", result)
			}
			process := result.Processes[0]
			if process.CurrentProcess != test.want {
				t.Fatalf("current=%v want=%v", process.CurrentProcess, test.want)
			}
			if test.want && process.CurrentProcessPath != current.Path {
				t.Fatal("current path not preserved")
			}
			if !test.want && process.CurrentProcessPath != "" {
				t.Fatal("unconfirmed current path leaked")
			}
			if process.ID != historicalProcessID(event.NewProcessID, event.Timestamp) || process.ProcessPath != event.NewProcessName || process.PID != event.NewProcessID || !process.MatchedLogin {
				t.Fatalf("unrelated evidence changed: %+v", process)
			}
			wantCount := uint32(0)
			if test.want {
				wantCount = 1
			}
			if result.Statistics.MatchedCurrentProcessCount != wantCount {
				t.Fatalf("wrong current count: %+v", result.Statistics)
			}
		})
	}
}

func TestHistoricalPIDReuseOnlyMatchesExactCurrentInstance(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	events := []model.ProcessEvent{
		{EventID: 4688, Timestamp: stamp.Add(-time.Hour), NewProcessID: 42, NewProcessName: `C:\Tools\app.exe`},
		{EventID: 4688, Timestamp: stamp, NewProcessID: 42, NewProcessName: `C:\Tools\app.exe`},
		{EventID: 4689, Timestamp: stamp, NewProcessID: 42, NewProcessName: `C:\Tools\app.exe`},
	}
	for _, reverse := range []bool{false, true} {
		input := append([]model.ProcessEvent(nil), events...)
		if reverse {
			input[0], input[2] = input[2], input[0]
		}
		result := AnalyzeProcessHistory(context.Background(), model.ProcessEventSnapshot{Events: input}, model.LoginAnalysis{}, []model.Process{{PID: 42, Path: `C:\Tools\app.exe`, StartTime: stamp}})
		if len(result.Processes) != 2 || result.Statistics.MatchedCurrentProcessCount != 1 {
			t.Fatalf("PID reuse result: %+v", result)
		}
		for _, process := range result.Processes {
			if process.CurrentProcess != process.Timestamp.Equal(stamp) {
				t.Fatalf("wrong instance: %+v", process)
			}
		}
	}
}

func TestHistoricalDuplicateCurrentPIDIsAmbiguous(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	current := model.Process{PID: 42, Path: `C:\Tools\app.exe`, StartTime: stamp}
	other := current
	other.StartTime = stamp.Add(time.Hour)
	for _, input := range [][]model.Process{{current, current}, {current, other}, {other, current}, {current, other, current}} {
		result := AnalyzeProcessHistory(context.Background(), model.ProcessEventSnapshot{Events: []model.ProcessEvent{{EventID: 4688, Timestamp: stamp, NewProcessID: 42, NewProcessName: current.Path}}}, model.LoginAnalysis{}, input)
		if len(result.Processes) != 1 || result.Processes[0].CurrentProcess || result.Processes[0].CurrentProcessPath != "" || result.Statistics.MatchedCurrentProcessCount != 0 {
			t.Fatalf("ambiguous PID matched: %+v", result)
		}
	}
}
