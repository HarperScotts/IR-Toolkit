package analyzer

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

func BuildTimeline(
	ctx context.Context,
	host model.HostInfo,
	login model.LoginAnalysis,
	processes []model.Process,
	network model.NetworkAnalysis,
	persistence model.PersistenceAnalysis,
	processHistory model.ProcessHistoryAnalysis,
	powerShell model.PowerShellAnalysis,
	windowsEvents model.WindowsEventAnalysis,
) model.Timeline {

	result := model.Timeline{
		Events: make(
			[]model.TimelineEvent,
			0,
		),
	}

	hostname := host.Hostname

	// ----------------------------------------
	// Login
	// ----------------------------------------

	appendLoginTimelineEvents(
		ctx,
		&result,
		hostname,
		login,
	)

	// ----------------------------------------
	// Process
	// ----------------------------------------

	appendProcessTimelineEvents(
		ctx,
		&result,
		hostname,
		processes,
	)

	// ----------------------------------------
	// Network
	// ----------------------------------------

	appendNetworkTimelineEvents(
		ctx,
		&result,
		hostname,
		network,
	)

	// ----------------------------------------
	// Persistence
	// ----------------------------------------

	appendPersistenceTimelineEvents(
		ctx,
		&result,
		hostname,
		persistence,
	)

	appendHistoricalProcessTimelineEvents(
		ctx,
		&result,
		hostname,
		processHistory,
	)

	appendPowerShellTimelineEvents(
		ctx,
		&result,
		hostname,
		powerShell,
	)
	appendWindowsActivityTimelineEvents(
		ctx,
		&result,
		hostname,
		windowsEvents,
	)

	// ----------------------------------------
	// Sort
	// ----------------------------------------

	sort.SliceStable(
		result.Events,
		func(i, j int) bool {

			left :=
				result.Events[i].
					Timestamp

			right :=
				result.Events[j].
					Timestamp

			// 无时间信息的事件放最后。
			if left.IsZero() &&
				right.IsZero() {

				return result.Events[i].ID <
					result.Events[j].ID
			}

			if left.IsZero() {
				return false
			}

			if right.IsZero() {
				return true
			}

			return left.Before(
				right,
			)
		},
	)

	buildTimelineStatistics(
		&result,
	)

	return result
}

// Login → Timeline
func appendLoginTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	login model.LoginAnalysis,
) {

	for _, session := range login.Sessions {

		select {
		case <-ctx.Done():
			return
		default:
		}

		eventType :=
			"LOGIN_SUCCESS"

		severity := ""

		if session.LogonType == 10 {
			eventType =
				"RDP_LOGIN"

			severity =
				"medium"
		}

		if session.Privileged &&
			session.SourceIP != "" {

			severity =
				"high"
		}

		user :=
			session.User

		if session.Domain != "" {

			user =
				session.Domain +
					`\` +
					session.User
		}

		description :=
			fmt.Sprintf(
				"%s logged on",
				user,
			)

		if session.SourceIP != "" {

			description =
				fmt.Sprintf(
					"%s logged on from %s",
					user,
					session.SourceIP,
				)
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: "timeline-login-" +
						sanitizeFindingID(
							session.LogonID,
						),

					Timestamp: session.Timestamp,

					Type: eventType,

					Category: "login",

					Severity: severity,

					Host: hostname,

					User: user,

					SourceIP: session.SourceIP,

					Description: description,

					LogonID: session.LogonID,

					Metadata: map[string]string{
						"logon_type": session.LogonTypeName,

						"authentication_package": session.AuthenticationPackage,

						"privileged": strconv.FormatBool(
							session.Privileged,
						),

						"workstation": session.Workstation,
					},
				},
			)
	}
}

// Process → Timeline
func appendProcessTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	processes []model.Process,
) {

	for _, process := range processes {

		select {
		case <-ctx.Done():
			return
		default:
		}

		// 没有 StartTime 就不伪造时间。
		if process.StartTime.IsZero() {
			continue
		}

		description :=
			fmt.Sprintf(
				"%s started",
				process.Name,
			)

		if process.CommandLine != "" {

			description =
				fmt.Sprintf(
					"%s started: %s",
					process.Name,
					process.CommandLine,
				)
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: fmt.Sprintf(
						"timeline-process-%d",
						process.PID,
					),

					Timestamp: process.StartTime,

					Type: "PROCESS_START",

					Category: "process",

					Host: hostname,

					User: process.User,

					PID: process.PID,

					PPID: process.PPID,

					Process: process.Name,

					Object: process.Path,

					Description: description,

					LogonID: process.AuthenticationID,

					Metadata: map[string]string{
						"path": process.Path,

						"command_line": process.CommandLine,

						"integrity": process.IntegrityLevel,

						"session_id": strconv.FormatUint(
							uint64(
								process.SessionID,
							),
							10,
						),
					},
				},
			)
	}
}

// Network → Timeline
func appendNetworkTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	network model.NetworkAnalysis,
) {

	for _, process := range network.Processes {

		for index, connection := range process.ExternalConnections {

			select {
			case <-ctx.Done():
				return
			default:
			}

			description :=
				fmt.Sprintf(
					"%s connected to %s:%d",
					process.ProcessName,
					connection.RemoteAddress,
					connection.RemotePort,
				)

			result.Events =
				append(
					result.Events,

					model.TimelineEvent{
						ID: fmt.Sprintf(
							"timeline-network-%d-%d",
							process.PID,
							index,
						),

						// 当前只是网络快照，
						// 没有可靠 ConnectionStartTime。
						Timestamp: time.Time{},

						Type: "NETWORK_SNAPSHOT",

						Category: "network",

						Host: hostname,

						User: process.User,

						PID: process.PID,

						Process: process.ProcessName,

						Object: fmt.Sprintf(
							"%s:%d",
							connection.RemoteAddress,
							connection.RemotePort,
						),

						Description: description,

						LogonID: process.AuthenticationID,

						Metadata: map[string]string{
							"protocol": connection.Protocol,

							"local_address": connection.LocalAddress,

							"local_port": strconv.FormatUint(
								uint64(
									connection.LocalPort,
								),
								10,
							),

							"remote_address": connection.RemoteAddress,

							"remote_port": strconv.FormatUint(
								uint64(
									connection.RemotePort,
								),
								10,
							),

							"state": connection.State,

							"time_source": "snapshot_only",
						},
					},
				)
		}
	}
}

// Persistence → Timeline
func appendPersistenceTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	persistence model.PersistenceAnalysis,
) {

	for _, finding := range persistence.Findings {

		select {
		case <-ctx.Done():
			return
		default:
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: "timeline-persistence-" +
						sanitizeFindingID(
							finding.ID,
						),

					Type: "PERSISTENCE_FINDING",

					Category: "persistence",

					Severity: finding.Severity,

					Host: hostname,

					User: finding.User,

					PID: finding.RelatedPID,

					Process: finding.RelatedProcess,

					Object: finding.ExecutablePath,

					Description: fmt.Sprintf(
						"%s: %s",
						finding.Title,
						finding.Name,
					),

					Metadata: map[string]string{
						"type": finding.Type,

						"command": finding.Command,

						"score": strconv.Itoa(
							finding.Score,
						),

						"time_source": "not_available",
					},
				},
			)
	}
}

// Timeline Statistics
func buildTimelineStatistics(
	result *model.Timeline,
) {

	result.Statistics.CategoryCounts =
		make(
			map[string]uint32,
		)

	result.Statistics.EventCount =
		uint32(
			len(result.Events),
		)

	for _, event := range result.Events {
		if event.Category != "" {

			result.Statistics.
				CategoryCounts[event.Category]++
		}

		switch event.Category {

		case "login":

			result.Statistics.
				LoginEvents++

		case "process":

			result.Statistics.
				ProcessEvents++

		case "network":

			result.Statistics.
				NetworkEvents++

		case "persistence":

			result.Statistics.
				PersistenceEvents++

		case "process_history":

			result.Statistics.
				HistoricalProcessEvents++

		case "powershell":

			result.Statistics.
				PowerShellEvents++
		}

		switch strings.ToLower(
			event.Severity,
		) {

		case "critical":

			result.Statistics.
				CriticalEvents++

		case "high":

			result.Statistics.
				HighEvents++

		case "medium":

			result.Statistics.
				MediumEvents++
		}
	}
}

func FilterTimelineByWindow(
	timeline model.Timeline,
	since *time.Time,
	until *time.Time,
) model.Timeline {

	if since == nil &&
		until == nil {

		return timeline
	}

	filtered :=
		model.Timeline{
			Events: make(
				[]model.TimelineEvent,
				0,
				len(
					timeline.Events,
				),
			),
		}

	for _, event := range timeline.Events {

		/*
			没有 Timestamp 的：

			NETWORK_SNAPSHOT
			PERSISTENCE_FINDING

			属于上下文证据，暂时保留。
		*/

		if event.Timestamp.IsZero() {

			filtered.Events =
				append(
					filtered.Events,
					event,
				)

			continue
		}

		if since != nil &&
			event.Timestamp.Before(
				*since,
			) {

			continue
		}

		if until != nil &&
			event.Timestamp.After(
				*until,
			) {

			continue
		}

		filtered.Events =
			append(
				filtered.Events,
				event,
			)
	}

	buildTimelineStatistics(
		&filtered,
	)

	return filtered
}

func appendHistoricalProcessTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	history model.ProcessHistoryAnalysis,
) {

	for _, process := range history.Processes {

		select {

		case <-ctx.Done():
			return

		default:
		}

		description :=
			fmt.Sprintf(
				"%s created",
				process.ProcessName,
			)

		if process.CommandLine != "" {

			description =
				fmt.Sprintf(
					"%s created: %s",
					process.ProcessName,
					process.CommandLine,
				)
		}

		user :=
			process.User

		if process.Domain != "" {

			user =
				process.Domain +
					`\` +
					process.User
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: "timeline-" +
						sanitizeFindingID(
							process.ID,
						),

					Timestamp: process.Timestamp,

					Type: "PROCESS_CREATE",

					Category: "process_history",

					Host: hostname,

					User: user,

					PID: process.PID,

					PPID: process.ParentPID,

					Process: process.ProcessName,

					Object: process.ProcessPath,

					Description: description,

					LogonID: process.LogonID,

					Metadata: map[string]string{
						"command_line": process.CommandLine,

						"parent_process": process.ParentProcessName,

						"token_elevation": process.TokenElevationType,

						"mandatory_label": process.MandatoryLabel,

						"evidence_source": "security_4688",
					},
				},
			)
	}
}

func appendPowerShellTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	analysis model.PowerShellAnalysis,
) {

	for _, block := range analysis.ScriptBlocks {

		select {

		case <-ctx.Done():
			return

		default:
		}

		description :=
			"PowerShell script block executed"

		if block.ScriptBlockID != "" {

			description =
				fmt.Sprintf(
					"PowerShell script block %s executed",
					block.ScriptBlockID,
				)
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: "timeline-powershell-" +
						sanitizeFindingID(
							block.ID,
						),

					Timestamp: block.Timestamp,

					Type: "POWERSHELL_SCRIPT",

					Category: "powershell",

					Host: hostname,

					User: block.User,

					PID: block.ProcessID,

					Process: block.RelatedProcessName,

					Object: block.Path,

					Description: description,

					LogonID: block.LogonID,

					Metadata: map[string]string{
						"script_block_id": block.ScriptBlockID,

						"script_sha256": block.ScriptSHA256,

						"fragment_count": fmt.Sprintf(
							"%d",
							block.FragmentCount,
						),

						"complete": fmt.Sprintf(
							"%t",
							block.Complete,
						),

						"preview": powerShellPreview(
							block.ScriptText,
							256,
						),

						"evidence_source": "powershell_4104",
					},
				},
			)
	}
}

func appendWindowsActivityTimelineEvents(
	ctx context.Context,
	result *model.Timeline,
	hostname string,
	analysis model.WindowsEventAnalysis,
) {

	for _, activity := range analysis.Activities {

		select {

		case <-ctx.Done():
			return

		default:
		}

		result.Events =
			append(
				result.Events,

				model.TimelineEvent{
					ID: "timeline-" +
						sanitizeFindingID(
							activity.ID,
						),

					Timestamp: activity.Timestamp,

					Type: activity.Type,

					Category: activity.Category,

					Severity: activity.Severity,

					Host: hostname,

					User: activity.User,

					SourceIP: activity.SourceIP,

					PID: activity.ProcessID,

					Object: activity.Object,

					Description: activity.Description,

					RelatedIDs: activity.RelatedIDs,

					Metadata: activity.Metadata,
				},
			)
	}
}
