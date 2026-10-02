package analyzer

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

func buildHistoricalCorrelationNodes(
	ctx context.Context,
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	login model.LoginAnalysis,
	processHistory model.ProcessHistoryAnalysis,
	powerShell model.PowerShellAnalysis,
	windowsEvents model.WindowsEventAnalysis,
) {

	// Login
	for _, session := range login.Sessions {

		select {
		case <-ctx.Done():
			return
		default:
		}

		if session.LogonID == "" {
			continue
		}

		addCorrelationNode(
			result,
			seen,
			model.HistoricalChainNode{
				ID: correlationLoginNodeID(
					session.LogonID,
				),

				Type: "login",

				Label: formatLoginLabel(
					session,
				),

				Timestamp: session.Timestamp,

				User: formatDomainUser(
					session.Domain,
					session.User,
				),

				LogonID: normalizeLogonID(
					session.LogonID,
				),

				SourceIP: session.SourceIP,

				Metadata: map[string]string{
					"logon_type": session.LogonTypeName,

					"privileged": fmt.Sprintf(
						"%t",
						session.Privileged,
					),
				},
			},
		)
	}

	// Historical Process
	for _, process := range processHistory.Processes {

		addCorrelationNode(
			result,
			seen,
			model.HistoricalChainNode{
				ID: process.ID,

				Type: "process",

				Label: fmt.Sprintf(
					"%s (%d)",
					process.ProcessName,
					process.PID,
				),

				Timestamp: process.Timestamp,

				User: formatDomainUser(
					process.Domain,
					process.User,
				),

				LogonID: process.LogonID,

				PID: process.PID,

				Object: process.ProcessPath,

				Metadata: map[string]string{
					"command_line": process.CommandLine,

					"parent_pid": fmt.Sprintf(
						"%d",
						process.ParentPID,
					),
				},
			},
		)
	}

	// PowerShell
	for _, block := range powerShell.ScriptBlocks {

		addCorrelationNode(
			result,
			seen,
			model.HistoricalChainNode{
				ID: block.ID,

				Type: "powershell",

				Label: "PowerShell ScriptBlock",

				Timestamp: block.Timestamp,

				User: block.User,

				LogonID: block.LogonID,

				PID: block.ProcessID,

				Object: block.Path,

				Metadata: map[string]string{
					"script_block_id": block.ScriptBlockID,

					"sha256": block.ScriptSHA256,

					"complete": fmt.Sprintf(
						"%t",
						block.Complete,
					),
				},
			},
		)
	}

	// Generic Windows Activities
	for _, activity := range windowsEvents.Activities {

		addCorrelationNode(
			result,
			seen,
			model.HistoricalChainNode{
				ID: activity.ID,

				Type: activity.Category,

				Label: activity.Type,

				Timestamp: activity.Timestamp,

				User: activity.User,

				PID: activity.ProcessID,

				SessionID: activity.SessionID,

				SourceIP: activity.SourceIP,

				Object: activity.Object,

				Metadata: activity.Metadata,
			},
		)
	}
}
