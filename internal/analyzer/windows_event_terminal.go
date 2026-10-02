package analyzer

import (
	"fmt"

	"ir-toolkit/internal/model"
)

func analyzeTerminalServicesEvent(
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

	user :=
		windowsEventData(
			event,
			"User",
			"UserName",
		)

	sessionID :=
		windowsEventData(
			event,
			"SessionID",
			"SessionId",
		)

	address :=
		windowsEventData(
			event,
			"Address",
			"SourceNetworkAddress",
			"ClientAddress",
		)

	var activityType string

	switch event.EventID {

	case 21:

		activityType =
			"RDP_SESSION_LOGON"

	case 22:

		activityType =
			"RDP_SHELL_START"

	case 23:

		activityType =
			"RDP_SESSION_LOGOFF"

	case 24:

		activityType =
			"RDP_SESSION_DISCONNECT"

	case 25:

		activityType =
			"RDP_SESSION_RECONNECT"

	default:

		return activities,
			nil
	}

	description :=
		fmt.Sprintf(
			"%s user=%s session=%s",
			activityType,
			user,
			sessionID,
		)

	if address != "" {

		description +=
			" source=" +
				address
	}

	activity :=
		model.WindowsActivity{
			ID: windowsActivityID(
				event,
				sessionID,
			),

			Timestamp: event.Timestamp,

			Type: activityType,

			Category: "remote_session",

			DefinitionID: event.DefinitionID,

			Channel: event.Channel,

			EventID: event.EventID,

			RecordID: event.RecordID,

			User: user,

			SourceIP: address,

			SessionID: sessionID,

			ProcessID: event.ProcessID,

			Description: description,

			Metadata: map[string]string{
				"session_id": sessionID,

				"source_address": address,
			},
		}

	activities =
		append(
			activities,
			activity,
		)

	return activities,
		nil
}
