package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func analyzeWMIEvent(
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

	namespace :=
		windowsEventData(
			event,
			"NamespaceName",
			"Namespace",
		)

	operation :=
		windowsEventData(
			event,
			"Operation",
		)

	user :=
		windowsEventData(
			event,
			"User",
			"UserName",
		)

	clientProcessID :=
		windowsEventUint32(
			event,
			"ClientProcessId",
			"ClientProcessID",
		)

	if clientProcessID == 0 {
		clientProcessID =
			event.ProcessID
	}

	resultCode :=
		windowsEventData(
			event,
			"ResultCode",
			"Result",
		)

	activityType :=
		"WMI_ACTIVITY"

	description :=
		fmt.Sprintf(
			"WMI activity Event ID %d",
			event.EventID,
		)

	switch event.EventID {

	case 5857:

		activityType =
			"WMI_PROVIDER_ACTIVITY"

	case 5858:

		activityType =
			"WMI_OPERATION_ERROR"

	case 5860:

		activityType =
			"WMI_TEMPORARY_CONSUMER_ACTIVITY"

	case 5861:

		activityType =
			"WMI_CONSUMER_ACTIVITY"
	}

	activity :=
		model.WindowsActivity{
			ID: windowsActivityID(
				event,
				namespace,
			),

			Timestamp: event.Timestamp,

			Type: activityType,

			Category: "wmi",

			DefinitionID: event.DefinitionID,

			Channel: event.Channel,

			EventID: event.EventID,

			RecordID: event.RecordID,

			User: user,

			ProcessID: clientProcessID,

			Object: namespace,

			Description: description,

			Metadata: map[string]string{
				"namespace": namespace,

				"operation": operation,

				"result": resultCode,
			},
		}

	activities =
		append(
			activities,
			activity,
		)

	finding :=
		analyzeWMIActivityFinding(
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

func analyzeWMIActivityFinding(
	activity model.WindowsActivity,
	event model.WindowsEvent,
) *model.WindowsEventFinding {

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	combined :=
		strings.ToLower(
			activity.Object +
				" " +
				activity.Metadata["operation"],
		)

	if strings.Contains(
		combined,
		"commandlineeventconsumer",
	) {

		score += 40

		reasons =
			append(
				reasons,
				"WMI activity references CommandLineEventConsumer",
			)
	}

	if strings.Contains(
		combined,
		"activescripteventconsumer",
	) {

		score += 40

		reasons =
			append(
				reasons,
				"WMI activity references ActiveScriptEventConsumer",
			)
	}

	if strings.Contains(
		combined,
		"__eventfilter",
	) {

		score += 20

		reasons =
			append(
				reasons,
				"WMI activity references an event filter",
			)
	}

	if strings.Contains(
		combined,
		"root\\subscription",
	) {

		score += 20

		reasons =
			append(
				reasons,
				"WMI activity references the subscription namespace",
			)
	}

	if score < 30 {
		return nil
	}

	return &model.WindowsEventFinding{
		ID: "WIN-WMI-" +
			sanitizeFindingID(
				activity.ID,
			),

		Timestamp: activity.Timestamp,

		Severity: windowsEventSeverity(
			score,
		),

		Type: "wmi_activity",

		Title: "High-interest WMI activity",

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
