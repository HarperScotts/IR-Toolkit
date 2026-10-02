package analyzer

import "ir-toolkit/internal/model"

func appendTimelineHighlights(
	report *model.CaseReport,
	timeline model.Timeline,
) {

	interesting :=
		map[string]bool{
			"login": true,

			"remote_session": true,

			"process_history": true,

			"powershell": true,

			"scheduled_task": true,

			"wmi": true,

			"persistence": true,
		}

	for _, event := range timeline.Events {

		if !interesting[event.Category] {

			continue
		}

		report.TimelineHighlights =
			append(
				report.TimelineHighlights,

				model.ReportTimelineEvent{
					Timestamp: event.Timestamp,

					Category: event.Category,

					Type: event.Type,

					User: event.User,

					Process: event.Process,

					Object: event.Object,

					Description: event.Description,
				},
			)

		if len(
			report.TimelineHighlights,
		) >= 50 {

			break
		}
	}
}
