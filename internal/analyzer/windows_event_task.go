package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func analyzeTaskSchedulerEvent(
	event model.WindowsEvent,
) (
	[]model.WindowsActivity,
	[]model.WindowsEventFinding,
) {

	activities :=
		make(
			[]model.WindowsActivity,
			0,
			1,
		)

	findings :=
		make(
			[]model.WindowsEventFinding,
			0,
		)

	taskName :=
		windowsEventData(
			event,
			"TaskName",
			"Task",
		)

	user :=
		windowsEventData(
			event,
			"UserName",
			"User",
		)

	action :=
		windowsEventData(
			event,
			"ActionName",
			"Action",
			"Path",
		)

	var activityType string
	var description string

	switch event.EventID {

	case 106:

		activityType =
			"SCHEDULED_TASK_REGISTERED"

		description =
			fmt.Sprintf(
				"Scheduled task registered: %s",
				taskName,
			)

	case 140:

		activityType =
			"SCHEDULED_TASK_UPDATED"

		description =
			fmt.Sprintf(
				"Scheduled task updated: %s",
				taskName,
			)

	case 141:

		activityType =
			"SCHEDULED_TASK_DELETED"

		description =
			fmt.Sprintf(
				"Scheduled task deleted: %s",
				taskName,
			)

	case 200:

		activityType =
			"SCHEDULED_TASK_ACTION_STARTED"

		description =
			fmt.Sprintf(
				"Scheduled task action started: %s",
				taskName,
			)

	case 201:

		activityType =
			"SCHEDULED_TASK_ACTION_COMPLETED"

		description =
			fmt.Sprintf(
				"Scheduled task action completed: %s",
				taskName,
			)

	default:

		return activities,
			findings
	}

	activity :=
		model.WindowsActivity{
			ID: windowsActivityID(
				event,
				taskName,
			),

			Timestamp: event.Timestamp,

			Type: activityType,

			Category: "scheduled_task",

			DefinitionID: event.DefinitionID,

			Channel: event.Channel,

			EventID: event.EventID,

			RecordID: event.RecordID,

			User: user,

			ProcessID: event.ProcessID,

			Object: taskName,

			Description: description,

			Metadata: map[string]string{
				"task_name": taskName,

				"action": action,
			},
		}

	activities =
		append(
			activities,
			activity,
		)

	finding :=
		analyzeTaskActivity(
			activity,
			event,
		)

	if finding != nil {

		findings =
			append(
				findings,
				*finding,
			)
	}

	return activities,
		findings
}

func analyzeTaskActivity(
	activity model.WindowsActivity,
	event model.WindowsEvent,
) *model.WindowsEventFinding {

	if event.EventID != 106 &&
		event.EventID != 140 {

		return nil
	}

	taskName :=
		strings.ToLower(
			activity.Object,
		)

	action :=
		strings.ToLower(
			activity.Metadata["action"],
		)

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	if strings.Contains(
		taskName,
		`\temp`,
	) ||
		strings.Contains(
			taskName,
			"update",
		) {

		score += 10
	}

	interestingActions :=
		[]string{
			"powershell",
			"pwsh",
			"cmd.exe",
			"mshta",
			"rundll32",
			"regsvr32",
			"wscript",
			"cscript",
			"certutil",
		}

	for _, value := range interestingActions {

		if strings.Contains(
			action,
			value,
		) {

			score += 30

			reasons =
				append(
					reasons,
					"scheduled task references a high-interest interpreter or utility",
				)

			break
		}
	}

	if strings.Contains(
		action,
		`\users\public\`,
	) ||
		strings.Contains(
			action,
			`\appdata\`,
		) ||
		strings.Contains(
			action,
			`\windows\temp\`,
		) {

		score += 30

		reasons =
			append(
				reasons,
				"scheduled task action references a writable or transient path",
			)
	}

	if score < 30 {
		return nil
	}

	return &model.WindowsEventFinding{
		ID: "WIN-TASK-" +
			sanitizeFindingID(
				activity.ID,
			),

		Timestamp: activity.Timestamp,

		Severity: windowsEventSeverity(
			score,
		),

		Type: "scheduled_task_activity",

		Title: "High-interest scheduled task activity",

		Score: score,

		EventID: event.EventID,

		DefinitionID: event.DefinitionID,

		User: activity.User,

		ProcessID: activity.ProcessID,

		Object: activity.Object,

		Reasons: uniqueStrings(
			reasons,
		),

		RelatedActivityIDs: []string{
			activity.ID,
		},

		Metadata: activity.Metadata,
	}
}
