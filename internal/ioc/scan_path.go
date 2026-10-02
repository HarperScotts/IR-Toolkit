package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func scanPathIOCs(
	ctx context.Context,
	result *model.IOCScanResult,
	rules []model.IOCValue,
	evidence CaseEvidence,
) {

	for _, rule := range rules {

		matchType :=
			rule.Match

		if matchType == "" {
			matchType = "exact"
		}

		for _, file := range evidence.Files.Files {

			select {
			case <-ctx.Done():
				return
			default:
			}

			if !matchString(
				normalizePath(
					file.Path,
				),
				normalizePath(
					rule.Value,
				),
				matchType,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "path",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: matchType,

						Source: "files",

						Object: file.Path,

						Path: file.Path,

						SHA256: file.SHA256,
					},
				)

			result.Statistics.
				PathMatches++
		}
		for _, process := range evidence.Processes {

			if !matchString(
				normalizePath(
					process.Path,
				),
				normalizePath(
					rule.Value,
				),
				matchType,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "path",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: matchType,

						Source: "process",

						Object: process.Path,

						PID: process.PID,

						Process: process.Name,

						Path: process.Path,

						CommandLine: process.CommandLine,
					},
				)

			result.Statistics.
				PathMatches++
		}
		for _, service := range evidence.Persistence.Services {

			executable :=
				extractPersistenceExecutable(
					service.BinaryPath,
				)

			if !matchString(
				normalizePath(
					executable,
				),
				normalizePath(
					rule.Value,
				),
				matchType,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "path",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: matchType,

						Source: "persistence",

						Object: service.BinaryPath,

						Path: executable,

						PersistenceType: "service",

						PersistenceName: service.Name,
					},
				)

			result.Statistics.
				PathMatches++
		}
		for _, entry := range evidence.Persistence.RunKeys {

			command :=
				entry.Command

			if entry.ExpandedCommand != "" {
				command =
					entry.ExpandedCommand
			}

			executable :=
				extractPersistenceExecutable(
					command,
				)

			if !matchString(
				normalizePath(
					executable,
				),
				normalizePath(
					rule.Value,
				),
				matchType,
				true,
			) {

				continue
			}

			result.Matches =
				append(
					result.Matches,

					model.IOCMatch{
						IOCType: "path",

						IOCValue: rule.Value,

						Description: rule.Description,

						MatchType: matchType,

						Source: "persistence",

						Object: command,

						Path: executable,

						PersistenceType: "run_key",

						PersistenceName: entry.Hive +
							`\` +
							entry.Key +
							`:` +
							entry.Name,
					},
				)

			result.Statistics.
				PathMatches++
		}
		for _, task := range evidence.Persistence.ScheduledTasks {

			for _, action := range task.Actions {

				executable :=
					extractPersistenceExecutable(
						action.Command,
					)

				if !matchString(
					normalizePath(
						executable,
					),
					normalizePath(
						rule.Value,
					),
					matchType,
					true,
				) {

					continue
				}

				result.Matches =
					append(
						result.Matches,

						model.IOCMatch{
							IOCType: "path",

							IOCValue: rule.Value,

							Description: rule.Description,

							MatchType: matchType,

							Source: "persistence",

							Object: action.Command,

							Path: executable,

							PersistenceType: "scheduled_task",

							PersistenceName: task.Path,
						},
					)

				result.Statistics.
					PathMatches++
			}
		}
	}
}
