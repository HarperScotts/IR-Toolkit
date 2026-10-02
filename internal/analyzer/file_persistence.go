package analyzer

import (
	"ir-toolkit/internal/model"
)

func buildPersistencePathIndex(
	persistence model.PersistenceSnapshot,
) map[string][]string {

	result :=
		make(
			map[string][]string,
		)

	// --------------------------------------------------
	// Services
	// --------------------------------------------------

	for _, service := range persistence.Services {

		executable :=
			extractExecutable(
				service.BinaryPath,
			)

		path :=
			normalizeArtifactPath(
				executable,
			)

		if path == "" {
			continue
		}

		result[path] =
			append(
				result[path],
				"service:"+
					service.Name,
			)
	}

	// --------------------------------------------------
	// Registry Run
	// --------------------------------------------------

	for _, entry := range persistence.RunKeys {

		command :=
			entry.Command

		if entry.ExpandedCommand != "" {
			command =
				entry.ExpandedCommand
		}

		executable :=
			extractExecutable(
				command,
			)

		path :=
			normalizeArtifactPath(
				executable,
			)

		if path == "" {
			continue
		}

		result[path] =
			append(
				result[path],
				"run_key:"+
					entry.Hive+
					`\`+
					entry.Key+
					`:`+
					entry.Name,
			)
	}

	// --------------------------------------------------
	// Scheduled Tasks
	// --------------------------------------------------

	for _, task := range persistence.ScheduledTasks {

		for _, action := range task.Actions {

			executable :=
				extractExecutable(
					action.Command,
				)

			path :=
				normalizeArtifactPath(
					executable,
				)

			if path == "" {
				continue
			}

			result[path] =
				append(
					result[path],
					"scheduled_task:"+
						task.Path,
				)
		}
	}

	for path, values := range result {

		result[path] =
			uniqueStrings(values)
	}

	return result
}
