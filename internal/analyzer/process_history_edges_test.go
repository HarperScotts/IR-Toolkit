package analyzer

import (
	"context"
	"testing"
	"time"

	"ir-toolkit/internal/model"
)

func parentEdgeFixture() (model.HistoricalProcess, model.HistoricalProcess) {
	stamp := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	parent := model.HistoricalProcess{ID: "parent", PID: 7, Timestamp: stamp, ProcessPath: `C:\Tools\parent.exe`, CurrentProcess: true, CurrentProcessPath: `C:\Tools\parent.exe`}
	child := model.HistoricalProcess{ID: "child", PID: 42, ParentPID: 7, Timestamp: stamp.Add(time.Minute), ParentProcessName: `C:\Tools\parent.exe`}
	return parent, child
}

func TestHistoricalParentRequiresUnambiguousInstance(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*model.HistoricalProcess, *model.HistoricalProcess) []model.HistoricalProcess
		want   bool
	}{
		{"confirmed current parent", func(*model.HistoricalProcess, *model.HistoricalProcess) []model.HistoricalProcess { return nil }, true},
		{"normalized creator path", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			c.ParentProcessName = `"c:/tools/PARENT.exe"`
			return nil
		}, true},
		{"missing creation record", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.PID = 8; return nil }, false},
		{"historical lifetime unknown", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.CurrentProcess = false; return nil }, false},
		{"missing creator path", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.ParentProcessName = ""; return nil }, false},
		{"creator path conflict", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			c.ParentProcessName = `C:\Tools\other.exe`
			return nil
		}, false},
		{"missing parent path", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.ProcessPath = ""; return nil }, false},
		{"missing current instance path", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.CurrentProcessPath = ""; return nil }, false},
		{"current instance path conflict", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			p.CurrentProcessPath = `C:\Tools\other.exe`
			return nil
		}, false},
		{"unknown parent time", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.Timestamp = time.Time{}; return nil }, false},
		{"unknown child time", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.Timestamp = time.Time{}; return nil }, false},
		{"same timestamp", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.Timestamp = p.Timestamp; return nil }, false},
		{"future parent", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			p.Timestamp = c.Timestamp.Add(time.Second)
			return nil
		}, false},
		{"self PID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.PID = p.PID; return nil }, false},
		{"self ID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.ID = p.ID; return nil }, false},
		{"missing child ID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.ID = ""; return nil }, false},
		{"missing parent ID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { p.ID = ""; return nil }, false},
		{"zero child PID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.PID = 0; return nil }, false},
		{"zero parent PID", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { c.ParentPID = 0; return nil }, false},
		{"equal-time multiple candidates", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			other := *p
			other.ID = "other"
			return []model.HistoricalProcess{other}
		}, false},
		{"duplicate candidate", func(p, c *model.HistoricalProcess) []model.HistoricalProcess { return []model.HistoricalProcess{*p} }, false},
		{"unordered unknown candidate", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			other := *p
			other.ID = "unknown"
			other.Timestamp = time.Time{}
			return []model.HistoricalProcess{other}
		}, false},
		{"newer conflicting instance must not fall back", func(p, c *model.HistoricalProcess) []model.HistoricalProcess {
			other := *p
			other.ID = "newer"
			other.Timestamp = p.Timestamp.Add(time.Second)
			other.ProcessPath = `C:\Tools\other.exe`
			other.CurrentProcess = false
			return []model.HistoricalProcess{other}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, child := parentEdgeFixture()
			extra := test.change(&parent, &child)
			input := append([]model.HistoricalProcess{parent, child}, extra...)
			for _, reversed := range []bool{false, true} {
				if reversed {
					for l, r := 0, len(input)-1; l < r; l, r = l+1, r-1 {
						input[l], input[r] = input[r], input[l]
					}
				}
				edges := buildHistoricalProcessEdges(input)
				if (len(edges) == 1) != test.want || len(edges) > 1 {
					t.Fatalf("edges=%+v want matched=%v", edges, test.want)
				}
				if test.want && (edges[0].ParentID != parent.ID || edges[0].ChildID != child.ID || edges[0].ParentPID != 7 || edges[0].ChildPID != 42 || edges[0].Type != "parent_child") {
					t.Fatalf("edge identity changed: %+v", edges)
				}
			}
		})
	}
}

func TestHistoricalCorrelationRevalidatesParentEdges(t *testing.T) {
	parent, child := parentEdgeFixture()
	edge := model.HistoricalProcessEdge{ParentID: parent.ID, ChildID: child.ID, ParentPID: parent.PID, ChildPID: child.PID, Type: "parent_child"}
	for _, test := range []struct {
		name   string
		change func(*model.ProcessHistoryAnalysis)
		want   int
	}{
		{"valid", func(*model.ProcessHistoryAnalysis) {}, 1},
		{"legacy unconfirmed parent", func(h *model.ProcessHistoryAnalysis) { h.Processes[0].CurrentProcess = false }, 0},
		{"legacy path conflict", func(h *model.ProcessHistoryAnalysis) { h.Processes[1].ParentProcessName = `C:\other.exe` }, 0},
		{"absent endpoint", func(h *model.ProcessHistoryAnalysis) { h.Processes = h.Processes[1:] }, 0},
		{"wrong PID", func(h *model.ProcessHistoryAnalysis) { h.Edges[0].ParentPID = 99 }, 0},
		{"wrong type", func(h *model.ProcessHistoryAnalysis) { h.Edges[0].Type = "unknown" }, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			history := model.ProcessHistoryAnalysis{Processes: []model.HistoricalProcess{parent, child}, Edges: []model.HistoricalProcessEdge{edge}}
			test.change(&history)
			result := AnalyzeHistoricalCorrelation(context.Background(), model.LoginAnalysis{}, history, model.PowerShellAnalysis{}, model.WindowsEventAnalysis{})
			if len(result.Edges) != test.want || result.Statistics.HighConfidenceEdgeCount != uint32(test.want) {
				t.Fatalf("unvalidated edge promoted: %+v", result)
			}
			if test.want == 1 && (result.Edges[0].Type != "parent_child" || result.Edges[0].From != parent.ID || result.Edges[0].To != child.ID) {
				t.Fatalf("correlation identity changed: %+v", result.Edges)
			}
		})
	}
}

func TestHistoricalParentPipelinePreservesRawCreatorEvidence(t *testing.T) {
	stamp := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	parentEvent := model.ProcessEvent{EventID: 4688, Timestamp: stamp, NewProcessID: 7, NewProcessName: `C:\Tools\parent.exe`}
	childEvent := model.ProcessEvent{EventID: 4688, Timestamp: stamp.Add(time.Minute), NewProcessID: 42, ProcessID: 7, ParentProcessName: parentEvent.NewProcessName, NewProcessName: `C:\Tools\child.exe`}
	for _, matched := range []bool{true, false} {
		current := model.Process{PID: 7, Path: parentEvent.NewProcessName, StartTime: stamp}
		if !matched {
			current.StartTime = stamp.Add(time.Hour)
		}
		history := AnalyzeProcessHistory(context.Background(), model.ProcessEventSnapshot{Events: []model.ProcessEvent{childEvent, parentEvent}}, model.LoginAnalysis{}, []model.Process{current})
		wantCount := uint32(0)
		if matched {
			wantCount = 1
		}
		if len(history.Edges) != int(wantCount) || history.Statistics.ParentChildEdgeCount != wantCount {
			t.Fatalf("parent pipeline: %+v", history)
		}
		if len(history.Processes) != 2 {
			t.Fatal("unresolved parent erased raw history")
		}
		for _, process := range history.Processes {
			if process.PID == 42 && (process.ID != historicalProcessID(42, childEvent.Timestamp) || process.ParentPID != 7 || process.ParentProcessName != childEvent.ParentProcessName) {
				t.Fatalf("raw creator evidence changed: %+v", process)
			}
		}
		correlation := AnalyzeHistoricalCorrelation(context.Background(), model.LoginAnalysis{}, history, model.PowerShellAnalysis{}, model.WindowsEventAnalysis{})
		if len(correlation.Edges) != int(wantCount) || correlation.Statistics.HighConfidenceEdgeCount != wantCount {
			t.Fatalf("correlation bypassed instance rule: %+v", correlation)
		}
	}
}
