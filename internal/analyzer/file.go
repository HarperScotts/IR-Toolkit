package analyzer

import (
	"context"

	"ir-toolkit/internal/model"
)

func AnalyzeFiles(
	ctx context.Context,
	files model.FileTriageSnapshot,
	network model.NetworkAnalysis,
	persistence model.PersistenceSnapshot,
) model.FileAnalysis {

	result :=
		model.FileAnalysis{
			Findings: make(
				[]model.FileFinding,
				0,
			),
		}

	result.Statistics.FileCount =
		uint32(
			len(files.Files),
		)

	processByPath :=
		make(
			map[string][]model.ProcessNetworkAnalysis,
		)

	for _, process := range network.Processes {

		path :=
			normalizeArtifactPath(
				process.ProcessPath,
			)

		if path == "" {
			continue
		}

		processByPath[path] =
			append(
				processByPath[path],
				process,
			)
	}

	persistenceByPath :=
		buildPersistencePathIndex(
			persistence,
		)

	for _, file := range files.Files {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		if file.Executable {
			result.Statistics.
				ExecutableCount++
		}

		path :=
			normalizeArtifactPath(
				file.Path,
			)

		processes :=
			processByPath[path]

		persistenceRefs :=
			persistenceByPath[path]

		if len(processes) > 0 {

			result.Statistics.
				ExecutedFileCount++
		}

		if len(persistenceRefs) > 0 {

			result.Statistics.
				PersistenceReferencedCount++
		}

		finding :=
			analyzeFileArtifact(
				file,
				processes,
				persistenceRefs,
			)

		if finding == nil {
			continue
		}

		result.Findings =
			append(
				result.Findings,
				*finding,
			)
	}

	result.Statistics.FindingCount =
		uint32(
			len(result.Findings),
		)

	for _, finding := range result.Findings {

		switch finding.Severity {

		case "critical":
			result.Statistics.
				CriticalCount++

		case "high":
			result.Statistics.
				HighCount++

		case "medium":
			result.Statistics.
				MediumCount++

		case "low":
			result.Statistics.
				LowCount++
		}
	}

	return result
}

func analyzeFileArtifact(
	file model.FileTriageItem,
	processes []model.ProcessNetworkAnalysis,
	persistenceRefs []string,
) *model.FileFinding {

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	if file.Executable &&
		isHighRiskFileLocation(
			file.Path,
		) {

		score += 35

		reasons =
			append(
				reasons,
				"executable or script is located in a high-interest writable directory",
			)
	}

	if file.Executable &&
		hasInternetZone(
			file,
		) {

		score += 20

		reasons =
			append(
				reasons,
				"file carries an Internet Zone.Identifier",
			)
	}

	if len(file.ADS) > 1 {

		score += 10

		reasons =
			append(
				reasons,
				"file contains alternate data streams",
			)
	}

	if len(processes) > 0 {

		score += 25

		reasons =
			append(
				reasons,
				"file path matches a currently observed process image",
			)
	}

	if len(persistenceRefs) > 0 {

		score += 30

		reasons =
			append(
				reasons,
				"file is referenced by persistence evidence",
			)
	}

	relatedPIDs :=
		make(
			[]uint32,
			0,
		)

	relatedProcesses :=
		make(
			[]string,
			0,
		)

	externalConnections :=
		make(
			[]model.NetworkConnection,
			0,
		)

	for _, process := range processes {

		relatedPIDs =
			append(
				relatedPIDs,
				process.PID,
			)

		relatedProcesses =
			append(
				relatedProcesses,
				process.ProcessName,
			)

		if len(
			process.ExternalConnections,
		) > 0 {

			score += 25

			reasons =
				append(
					reasons,
					"matching process has external network activity",
				)

			externalConnections =
				append(
					externalConnections,
					process.ExternalConnections...,
				)
		}
	}

	if score < 30 {
		return nil
	}

	finding :=
		&model.FileFinding{
			ID: "FILE-" +
				sanitizeFindingID(
					file.Path,
				),

			Title: "Suspicious file artifact",

			Path: file.Path,

			SHA256: file.SHA256,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),

			Executed: len(processes) > 0,

			RelatedPIDs: uniqueUint32(
				relatedPIDs,
			),

			RelatedProcesses: uniqueStrings(
				relatedProcesses,
			),

			Persistence: uniqueStrings(
				persistenceRefs,
			),

			ExternalConnections: externalConnections,
		}

	finding.Severity =
		fileSeverity(score)

	return finding
}
