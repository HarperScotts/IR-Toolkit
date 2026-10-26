package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/model"
)

func TestAnalyzeTimelineOutputsShareCollectionWindow(t *testing.T) {
	since := time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)
	until := since.Add(time.Hour)
	for _, test := range []struct {
		name         string
		since, until *time.Time
		want         int
	}{
		{"both inclusive bounds", &since, &until, 4},
		{"since only", &since, nil, 5},
		{"until only", nil, &until, 5},
		{"unbounded", nil, nil, 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeCentralJSON(t, root, "manifest.json", model.Manifest{CaseID: "timeline-window", Hostname: "synthetic-host", CollectionSince: test.since, CollectionUntil: test.until})
			for path, value := range map[string]any{
				"host/host.json":         model.HostInfo{Hostname: "synthetic-host"},
				"process/processes.json": []model.Process{}, "network/network.json": model.NetworkSnapshot{Warnings: []string{"synthetic network scope warning"}},
				"login/login.json": model.LoginSnapshot{}, "files/files.json": model.FileTriageSnapshot{},
				"persistence/persistence.json":   model.PersistenceSnapshot{},
				"capabilities/capabilities.json": model.AuditCapabilitySnapshot{},
				"events/powershell_events.json":  map[string]any{}, "events/windows_events.json": map[string]any{},
			} {
				writeCentralJSON(t, root, path, value)
			}
			var events []model.ProcessEvent
			for index, stamp := range []time.Time{since.Add(-time.Nanosecond), since, since.Add(time.Minute), until, until.Add(time.Nanosecond), {}} {
				events = append(events, model.ProcessEvent{EventID: 4688, Timestamp: stamp, NewProcessID: uint32(index + 100), NewProcessName: `C:\Tools\ordinary.exe`})
			}
			writeCentralJSON(t, root, "events/process_events.json", model.ProcessEventSnapshot{Events: events})
			raw := map[string][]byte{}
			for _, path := range []string{"manifest.json", "process/processes.json", "events/process_events.json"} {
				data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
				if err != nil {
					t.Fatal(err)
				}
				raw[path] = data
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			if err := runAnalyze(cmd, []string{root}); err != nil {
				t.Fatal(err)
			}
			var timeline model.Timeline
			readTimelineTestJSON(t, filepath.Join(root, "timeline", "timeline.json"), &timeline)
			if len(timeline.Events) != test.want || timeline.Statistics.EventCount != uint32(test.want) || timeline.Statistics.HistoricalProcessEvents != uint32(test.want) || timeline.Statistics.CategoryCounts["process_history"] != uint32(test.want) {
				t.Fatalf("unfiltered timeline/statistics: %+v", timeline)
			}
			zeroCount := 0
			for _, event := range timeline.Events {
				if event.Timestamp.IsZero() {
					zeroCount++
					continue
				}
				if test.since != nil && event.Timestamp.Before(*test.since) || test.until != nil && event.Timestamp.After(*test.until) {
					t.Fatalf("outside-window event persisted: %+v", event)
				}
			}
			if zeroCount != 1 {
				t.Fatalf("unknown-time context lost: %d", zeroCount)
			}
			file, err := os.Open(filepath.Join(root, "timeline", "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var lines []model.TimelineEvent
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				var event model.TimelineEvent
				if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
					_ = file.Close()
					t.Fatal(err)
				}
				lines = append(lines, event)
			}
			scanErr, closeErr := scanner.Err(), file.Close()
			if scanErr != nil || closeErr != nil {
				t.Fatal(scanErr, closeErr)
			}
			if !reflect.DeepEqual(lines, timeline.Events) {
				t.Fatal("JSONL differs from timeline JSON")
			}
			var report model.CaseReport
			readTimelineTestJSON(t, filepath.Join(root, "analysis", "report.json"), &report)
			if !strings.Contains(strings.Join(report.EvidenceGaps, " "), "synthetic network scope warning") {
				t.Fatal("network collection warning lost from report")
			}
			var highlights []model.ReportTimelineEvent
			for _, event := range timeline.Events {
				highlights = append(highlights, model.ReportTimelineEvent{Timestamp: event.Timestamp, Category: event.Category, Type: event.Type, User: event.User, Process: event.Process, Object: event.Object, Description: event.Description})
			}
			if !reflect.DeepEqual(report.TimelineHighlights, highlights) {
				t.Fatal("report highlights use a different timeline window")
			}
			for path, before := range raw {
				after, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("raw evidence changed: %s, %v", path, err)
				}
			}
		})
	}
}

func readTimelineTestJSON(t *testing.T, path string, target any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}
