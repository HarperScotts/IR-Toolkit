package analyzer

import (
	"context"
	"strings"

	"ir-toolkit/internal/model"
)

func AnalyzePersistence(
	ctx context.Context,
	persistence model.PersistenceSnapshot,
	network model.NetworkAnalysis,
) model.PersistenceAnalysis {

	result :=
		model.PersistenceAnalysis{

			Findings: make(
				[]model.PersistenceFinding,
				0,
			),
		}

	result.Statistics.ServiceCount =
		uint32(
			len(
				persistence.Services,
			),
		)

	result.Statistics.RunKeyCount =
		uint32(
			len(
				persistence.RunKeys,
			),
		)

	result.Statistics.ScheduledTaskCount =
		uint32(
			len(
				persistence.ScheduledTasks,
			),
		)

	processMap :=
		make(
			map[uint32]model.ProcessNetworkAnalysis,
			len(network.Processes),
		)

	pathMap :=
		make(
			map[string]model.ProcessNetworkAnalysis,
			len(network.Processes),
		)

	for _, process := range network.Processes {

		processMap[process.PID] =
			process

		if process.ProcessPath != "" {

			pathMap[normalizeExecutablePath(
				process.ProcessPath,
			)] = process
		}
	}

	// --------------------------------------------------
	// Services
	// --------------------------------------------------

	for _, service := range persistence.Services {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		if finding :=
			analyzeServicePersistence(
				service,
				processMap,
				pathMap,
			); finding != nil {

			result.Findings =
				append(
					result.Findings,
					*finding,
				)
		}
	}

	// --------------------------------------------------
	// Run Keys
	// --------------------------------------------------

	for _, runKey := range persistence.RunKeys {

		select {

		case <-ctx.Done():
			return result

		default:
		}

		if finding :=
			analyzeRunKeyPersistence(
				runKey,
				pathMap,
			); finding != nil {

			result.Findings =
				append(
					result.Findings,
					*finding,
				)
		}
	}

	// --------------------------------------------------
	// Scheduled Tasks
	// --------------------------------------------------

	for _, task := range persistence.ScheduledTasks {

		for _, action := range task.Actions {

			select {

			case <-ctx.Done():
				return result

			default:
			}

			result.Statistics.
				AnalyzedActions++

			if finding :=
				analyzeTaskPersistence(
					task,
					action,
					pathMap,
				); finding != nil {

				result.Findings =
					append(
						result.Findings,
						*finding,
					)
			}
		}
	}

	// --------------------------------------------------
	// Statistics
	// --------------------------------------------------

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

func analyzeServicePersistence(
	service model.ServiceInfo,
	processMap map[uint32]model.ProcessNetworkAnalysis,
	pathMap map[string]model.ProcessNetworkAnalysis,
) *model.PersistenceFinding {

	command :=
		service.BinaryPath

	executable :=
		extractExecutable(
			command,
		)

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	// --------------------------------------------------
	// Location
	// --------------------------------------------------

	if isUserWritableOrTransientPath(
		executable,
	) {

		score += 50

		reasons =
			append(
				reasons,
				"service executable is located in a user-writable or transient directory",
			)
	}

	// --------------------------------------------------
	// Interpreter / LOLBin as service binary
	// --------------------------------------------------

	if isSuspiciousPersistenceExecutable(
		executable,
	) {

		score += 30

		reasons =
			append(
				reasons,
				"service uses a command shell, script engine, or commonly abused utility",
			)
	}

	if hasSuspiciousPersistenceCommand(
		command,
	) {

		score += 35

		reasons =
			append(
				reasons,
				"service command line contains suspicious execution or download parameters",
			)
	}

	// --------------------------------------------------
	// Automatic + SYSTEM increases context
	// --------------------------------------------------

	if service.StartType ==
		"Automatic" {

		score += 5
	}

	if isSystemAccount(
		service.Account,
	) {

		score += 5
	}

	var relatedProcess model.ProcessNetworkAnalysis
	var processExists bool

	// Service PID 是最可靠的关联方式。
	if service.PID != 0 {

		relatedProcess,
			processExists =
			processByPID(
				processMap,
				service.PID,
			)
	}

	// 如果服务当前没运行，尝试通过路径找进程。
	if !processExists &&
		executable != "" {

		relatedProcess,
			processExists =
			pathMap[normalizeExecutablePath(
				executable,
			)]
	}

	if processExists &&
		len(
			relatedProcess.
				ExternalConnections,
		) > 0 {

		score += 40

		reasons =
			append(
				reasons,
				"related service process has an external network connection",
			)
	}

	// 没有足够异常线索，不产生 Finding。
	if score < 30 {
		return nil
	}

	finding :=
		&model.PersistenceFinding{

			ID: "PERSIST-SERVICE-" +
				sanitizeFindingID(
					service.Name,
				),

			Type: "service",

			Name: service.Name,

			Title: "Suspicious Windows service persistence",

			Command: command,

			ExecutablePath: executable,

			User: service.Account,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),
		}

	finding.Severity =
		persistenceSeverity(
			score,
		)

	if processExists {

		finding.RelatedPID =
			relatedProcess.PID

		finding.RelatedProcess =
			relatedProcess.ProcessName

		finding.ExternalConnections =
			relatedProcess.
				ExternalConnections
	}

	return finding
}

func analyzeRunKeyPersistence(
	entry model.RegistryRunEntry,
	pathMap map[string]model.ProcessNetworkAnalysis,
) *model.PersistenceFinding {

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

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	if isUserWritableOrTransientPath(
		executable,
	) {

		score += 50

		reasons =
			append(
				reasons,
				"Run key executable is located in a user-writable or transient directory",
			)
	}

	if isSuspiciousPersistenceExecutable(
		executable,
	) {

		score += 25

		reasons =
			append(
				reasons,
				"Run key launches a command shell, script engine, or commonly abused utility",
			)
	}

	if hasSuspiciousPersistenceCommand(
		command,
	) {

		score += 35

		reasons =
			append(
				reasons,
				"Run key command contains suspicious execution or download parameters",
			)
	}

	process,
		processExists :=
		pathMap[normalizeExecutablePath(
			executable,
		)]

	if processExists &&
		len(
			process.ExternalConnections,
		) > 0 {

		score += 40

		reasons =
			append(
				reasons,
				"matching process has an external network connection",
			)
	}

	if score < 30 {
		return nil
	}

	finding :=
		&model.PersistenceFinding{

			ID: "PERSIST-RUN-" +
				sanitizeFindingID(
					entry.Hive+
						"-"+
						entry.Name,
				),

			Type: "run_key",

			Name: entry.Hive +
				`\` +
				entry.Key +
				` -> ` +
				entry.Name,

			Title: "Suspicious Registry Run key persistence",

			Command: command,

			ExecutablePath: executable,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),
		}

	finding.Severity =
		persistenceSeverity(
			score,
		)

	if processExists {

		finding.RelatedPID =
			process.PID

		finding.RelatedProcess =
			process.ProcessName

		finding.ExternalConnections =
			process.
				ExternalConnections
	}

	return finding
}

func analyzeTaskPersistence(
	task model.ScheduledTask,
	action model.ScheduledTaskAction,
	pathMap map[string]model.ProcessNetworkAnalysis,
) *model.PersistenceFinding {

	command :=
		strings.TrimSpace(
			action.Command +
				" " +
				action.Arguments,
		)

	executable :=
		extractExecutable(
			action.Command,
		)

	score := 0

	reasons :=
		make(
			[]string,
			0,
		)

	if isUserWritableOrTransientPath(
		executable,
	) {

		score += 50

		reasons =
			append(
				reasons,
				"scheduled task executable is located in a user-writable or transient directory",
			)
	}

	if isSuspiciousPersistenceExecutable(
		executable,
	) {

		score += 25

		reasons =
			append(
				reasons,
				"scheduled task launches a command shell, script engine, or commonly abused utility",
			)
	}

	if hasSuspiciousPersistenceCommand(
		command,
	) {

		score += 35

		reasons =
			append(
				reasons,
				"scheduled task command contains suspicious execution or download parameters",
			)
	}

	if task.Hidden != nil &&
		*task.Hidden {

		score += 10

		reasons =
			append(
				reasons,
				"scheduled task is hidden",
			)
	}

	if strings.EqualFold(
		task.UserID,
		"SYSTEM",
	) {

		score += 5
	}

	if strings.EqualFold(
		task.RunLevel,
		"HighestAvailable",
	) {

		score += 5
	}

	if hasPersistenceTrigger(
		task.TriggerTypes,
	) {

		score += 5
	}

	process,
		processExists :=
		pathMap[normalizeExecutablePath(
			executable,
		)]

	if processExists &&
		len(
			process.ExternalConnections,
		) > 0 {

		score += 40

		reasons =
			append(
				reasons,
				"matching task process has an external network connection",
			)
	}

	if score < 30 {
		return nil
	}

	finding :=
		&model.PersistenceFinding{

			ID: "PERSIST-TASK-" +
				sanitizeFindingID(
					task.Path,
				),

			Type: "scheduled_task",

			Name: task.Path,

			Title: "Suspicious scheduled task persistence",

			Command: command,

			ExecutablePath: executable,

			User: task.UserID,

			Score: score,

			Reasons: uniqueStrings(
				reasons,
			),
		}

	finding.Severity =
		persistenceSeverity(
			score,
		)

	if processExists {

		finding.RelatedPID =
			process.PID

		finding.RelatedProcess =
			process.ProcessName

		finding.ExternalConnections =
			process.
				ExternalConnections
	}

	return finding
}
