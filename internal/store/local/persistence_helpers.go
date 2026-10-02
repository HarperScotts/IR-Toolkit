package local

import (
	"ir-toolkit/internal/model"
	"strings"
)

func persistenceEvidenceID(
	evidenceType string,
	name string,
	extra string,
) string {

	return strings.ToLower(
		strings.Join(
			[]string{
				"persistence",
				strings.TrimSpace(evidenceType),
				strings.TrimSpace(name),
				strings.TrimSpace(extra),
			},
			":",
		),
	)
}

func persistenceFindingKey(
	evidenceType string,
	name string,
) string {

	return strings.ToLower(
		strings.TrimSpace(evidenceType),
	) +
		"|" +
		strings.ToLower(
			strings.TrimSpace(name),
		)
}

func servicePersistenceItem(
	service model.ServiceInfo,
	findingMap map[string]model.PersistenceFinding,
) PersistenceItem {

	id :=
		persistenceEvidenceID(
			"service",
			service.Name,
			"",
		)

	item :=
		PersistenceItem{
			ID: id,

			Type: "service",

			Name: service.Name,

			Title: firstNonEmpty(
				service.DisplayName,
				service.Name,
			),

			Command: service.BinaryPath,

			User: service.Account,

			PID: service.PID,

			Object: service.BinaryPath,
		}

	key :=
		persistenceFindingKey(
			item.Type,
			item.Name,
		)

	if finding, ok :=
		findingMap[key]; ok {

		item.HasFinding =
			true

		item.FindingID =
			finding.ID
	}

	return item
}

func runKeyPersistenceItem(
	entry model.RegistryRunEntry,
	findingMap map[string]model.PersistenceFinding,
) PersistenceItem {

	extra :=
		entry.Hive +
			"\\" +
			entry.Key +
			"|" +
			entry.View

	id :=
		persistenceEvidenceID(
			"run_key",
			entry.Name,
			extra,
		)

	item :=
		PersistenceItem{
			ID: id,

			Type: "run_key",

			Name: entry.Name,

			Title: entry.Hive +
				"\\" +
				entry.Key +
				" → " +
				entry.Name,

			Command: firstNonEmpty(
				entry.ExpandedCommand,
				entry.Command,
			),

			Timestamp: entry.KeyModifiedAt,

			Object: firstNonEmpty(
				entry.ExpandedCommand,
				entry.Command,
			),
		}

	key :=
		persistenceFindingKey(
			item.Type,
			item.Name,
		)

	if finding, ok :=
		findingMap[key]; ok {

		item.HasFinding =
			true

		item.FindingID =
			finding.ID
	}

	return item
}

func scheduledTaskCommand(
	task model.ScheduledTask,
) string {

	parts :=
		make(
			[]string,
			0,
			len(task.Actions),
		)

	for _, action := range task.Actions {

		value :=
			strings.TrimSpace(
				action.Command,
			)

		if action.Arguments != "" {

			if value != "" {
				value += " "
			}

			value +=
				action.Arguments
		}

		if value != "" {

			parts =
				append(
					parts,
					value,
				)
		}
	}

	return strings.Join(
		parts,
		" | ",
	)
}

func scheduledTaskPersistenceItem(
	task model.ScheduledTask,
	findings map[string]model.PersistenceFinding,
) PersistenceItem {

	id :=
		persistenceEvidenceID(
			"scheduled_task",
			task.Name,
			task.Path,
		)

	command :=
		scheduledTaskCommand(
			task,
		)

	item :=
		PersistenceItem{
			ID: id,

			Type: "scheduled_task",

			Name: task.Name,

			Title: firstNonEmpty(
				task.Path,
				task.Name,
			),

			Command: command,

			User: task.UserID,

			Timestamp: task.ModifiedAt,

			Object: firstNonEmpty(
				command,
				task.Path,
				task.FilePath,
			),
		}

	key :=
		persistenceFindingKey(
			item.Type,
			item.Name,
		)

	if finding, ok :=
		findings[key]; ok {

		item.HasFinding =
			true

		item.FindingID =
			finding.ID
	}

	return item
}
