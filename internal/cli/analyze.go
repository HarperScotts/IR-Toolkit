package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"ir-toolkit/internal/analyzer"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze <case-dir>",
	Short: "Analyze collected incident response evidence",

	Args: cobra.ExactArgs(1),

	RunE: runAnalyze,
}

func init() {

	// root.go 不需要修改。
	// analyze 命令在这里自行注册。
	rootCmd.AddCommand(
		analyzeCmd,
	)
}

func runAnalyze(
	cmd *cobra.Command,
	args []string,
) error {

	caseDir :=
		filepath.Clean(
			args[0],
		)

	// --------------------------------------------------
	// Validate case directory
	// --------------------------------------------------

	info, err :=
		os.Stat(caseDir)

	if err != nil {

		return fmt.Errorf(
			"case directory %q: %w",
			caseDir,
			err,
		)
	}

	if !info.IsDir() {

		return fmt.Errorf(
			"%q is not a directory",
			caseDir,
		)
	}

	processFile :=
		filepath.Join(
			caseDir,
			"process",
			"processes.json",
		)

	networkFile :=
		filepath.Join(
			caseDir,
			"network",
			"network.json",
		)

	outputFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"network_analysis.json",
		)

	persistenceFile :=
		filepath.Join(
			caseDir,
			"persistence",
			"persistence.json",
		)

	persistenceOutputFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"persistence_analysis.json",
		)

	loginFile :=
		filepath.Join(
			caseDir,
			"login",
			"login.json",
		)

	loginOutputFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"login_analysis.json",
		)

	activityOutputFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"activity_analysis.json",
		)

	hostFile :=
		filepath.Join(
			caseDir,
			"host",
			"host.json",
		)

	timelineJSONFile :=
		filepath.Join(
			caseDir,
			"timeline",
			"timeline.json",
		)

	timelineJSONLFile :=
		filepath.Join(
			caseDir,
			"timeline",
			"events.jsonl",
		)

	manifestFile :=
		filepath.Join(
			caseDir,
			"manifest.json",
		)

	fileEvidenceFile :=
		filepath.Join(
			caseDir,
			"files",
			"files.json",
		)

	fileAnalysisOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"file_analysis.json",
		)

	processEventsFile :=
		filepath.Join(
			caseDir,
			"events",
			"process_events.json",
		)

	processHistoryOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"process_history_analysis.json",
		)

	powerShellEventsFile :=
		filepath.Join(
			caseDir,
			"events",
			"powershell_events.json",
		)

	powerShellAnalysisOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"powershell_analysis.json",
		)

	capabilityFile :=
		filepath.Join(
			caseDir,
			"capabilities",
			"capabilities.json",
		)

	windowsEventsFile :=
		filepath.Join(
			caseDir,
			"events",
			"windows_events.json",
		)

	windowsEventAnalysisOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"windows_event_analysis.json",
		)

	historicalCorrelationOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"historical_correlation.json",
		)

	reportJSONOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"report.json",
		)

	reportTextOutput :=
		filepath.Join(
			caseDir,
			"analysis",
			"report.txt",
		)

	iocMatchesFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"ioc_matches.json",
		)

	// --------------------------------------------------
	// Load evidence
	// --------------------------------------------------

	processes, err :=
		analyzer.LoadProcesses(
			processFile,
		)

	if err != nil {
		return err
	}

	connections, err :=
		analyzer.LoadNetworkConnections(
			networkFile,
		)

	if err != nil {
		return err
	}

	powerShellEvents, err :=
		analyzer.LoadPowerShellEvents(
			powerShellEventsFile,
		)

	if err != nil {
		return err
	}

	capabilities, err :=
		analyzer.LoadCapabilities(
			capabilityFile,
		)

	if err != nil {
		return err
	}

	windowsEvents, err :=
		analyzer.LoadWindowsEvents(
			windowsEventsFile,
		)

	if err != nil {
		return err
	}

	iocResult, err :=
		analyzer.TryLoadIOCScanResult(
			iocMatchesFile,
		)

	if err != nil {
		return err
	}

	// --------------------------------------------------
	// Analyze
	// --------------------------------------------------

	ctx := cmd.Context()

	if ctx == nil {
		ctx =
			context.Background()
	}

	engine :=
		analyzer.
			NewProcessNetworkAnalyzer()

	result :=
		engine.Analyze(
			ctx,
			processes,
			connections,
		)

	loginSnapshot, err :=
		analyzer.LoadLogin(
			loginFile,
		)

	if err != nil {
		return err
	}

	// --------------------------------------------------
	// Write result
	// --------------------------------------------------

	fileSnapshot, err :=
		analyzer.LoadFiles(
			fileEvidenceFile,
		)

	if err != nil {
		return err
	}

	// 持久化
	persistenceSnapshot, err :=
		analyzer.LoadPersistence(
			persistenceFile,
		)

	if err != nil {
		return err
	}

	persistenceResult :=
		analyzer.AnalyzePersistence(
			ctx,
			persistenceSnapshot,
			result,
		)

	if err :=
		analyzer.WritePersistenceAnalysis(
			persistenceOutputFile,
			persistenceResult,
		); err != nil {

		return err
	}

	if err :=
		analyzer.WriteNetworkAnalysis(
			outputFile,
			result,
		); err != nil {

		return err
	}

	fileResult :=
		analyzer.AnalyzeFiles(
			ctx,
			fileSnapshot,
			result,
			persistenceSnapshot,
		)

	if err :=
		analyzer.WriteFileAnalysis(
			fileAnalysisOutput,
			fileResult,
		); err != nil {

		return err
	}

	// 进程关系
	relationshipOutputFile :=
		filepath.Join(
			caseDir,
			"analysis",
			"process_relationship_analysis.json",
		)

	relationshipResult :=
		analyzer.AnalyzeProcessRelationships(
			ctx,
			processes,
			result,
		)

	if err :=
		analyzer.WriteProcessRelationshipAnalysis(
			relationshipOutputFile,
			relationshipResult,
		); err != nil {

		return err
	}

	loginResult :=
		analyzer.AnalyzeLogin(
			ctx,
			loginSnapshot,
			result,
		)

	if err :=
		analyzer.WriteLoginAnalysis(
			loginOutputFile,
			loginResult,
		); err != nil {

		return err
	}

	activityResult :=
		analyzer.AnalyzeActivity(
			ctx,
			loginResult,
			relationshipResult,
			result,
			persistenceResult,
		)

	if err :=
		analyzer.WriteActivityAnalysis(
			activityOutputFile,
			activityResult,
		); err != nil {

		return err
	}

	hostInfo, err :=
		analyzer.LoadHost(
			hostFile,
		)

	if err != nil {
		return err
	}

	processEvents, err :=
		analyzer.LoadProcessEvents(
			processEventsFile,
		)

	if err != nil {
		return err
	}

	processHistoryResult :=
		analyzer.AnalyzeProcessHistory(
			ctx,
			processEvents,
			loginResult,
			processes,
		)

	if err :=
		analyzer.WriteProcessHistoryAnalysis(
			processHistoryOutput,
			processHistoryResult,
		); err != nil {

		return err
	}

	powerShellResult :=
		analyzer.AnalyzePowerShell(
			ctx,
			powerShellEvents,
			processHistoryResult,
		)

	if err :=
		analyzer.WritePowerShellAnalysis(
			powerShellAnalysisOutput,
			powerShellResult,
		); err != nil {

		return err
	}

	windowsEventResult :=
		analyzer.AnalyzeWindowsEvents(
			ctx,
			windowsEvents,
		)

	if err :=
		analyzer.WriteWindowsEventAnalysis(
			windowsEventAnalysisOutput,
			windowsEventResult,
		); err != nil {

		return err
	}

	historicalCorrelationResult :=
		analyzer.AnalyzeHistoricalCorrelation(
			ctx,
			loginResult,
			processHistoryResult,
			powerShellResult,
			windowsEventResult,
		)

	if err :=
		analyzer.WriteHistoricalCorrelationAnalysis(
			historicalCorrelationOutput,
			historicalCorrelationResult,
		); err != nil {

		return err
	}

	timelineResult :=
		analyzer.BuildTimeline(
			ctx,
			hostInfo,
			loginResult,
			processes,
			result,
			persistenceResult,
			processHistoryResult,
			powerShellResult,
			windowsEventResult,
		)

	if err :=
		analyzer.WriteTimeline(
			timelineJSONFile,
			timelineResult,
		); err != nil {

		return err
	}

	if err :=
		analyzer.WriteTimelineJSONL(
			timelineJSONLFile,
			timelineResult,
		); err != nil {

		return err
	}

	manifest, err :=
		analyzer.LoadManifest(
			manifestFile,
		)

	if err != nil {
		return err
	}

	timelineResult =
		analyzer.FilterTimelineByWindow(
			timelineResult,
			manifest.CollectionSince,
			manifest.CollectionUntil,
		)

	// 放在所有 Analyzer 和 Timeline 都完成以后
	caseReport :=
		analyzer.BuildCaseReport(
			caseDir,
			hostInfo,
			manifest,
			capabilities,
			fileResult,
			persistenceResult,
			powerShellResult,
			windowsEventResult,
			processHistoryResult,
			historicalCorrelationResult,
			timelineResult,
			iocResult,
		)
	if err :=
		analyzer.WriteCaseReportJSON(
			reportJSONOutput,
			caseReport,
		); err != nil {

		return err
	}

	if err :=
		analyzer.WriteCaseReportText(
			reportTextOutput,
			caseReport,
		); err != nil {

		return err
	}

	// --------------------------------------------------
	// Summary
	// --------------------------------------------------

	indicatorProcesses := 0

	for _, process := range result.Processes {

		if len(
			process.Indicators,
		) > 0 {

			indicatorProcesses++
		}
	}

	fmt.Println(
		"========================================",
	)

	fmt.Println(
		"          IR Toolkit Analysis",
	)

	fmt.Println(
		"========================================",
	)

	fmt.Printf(
		"Case                   : %s\n",
		caseDir,
	)

	fmt.Printf(
		"Processes              : %d\n",
		result.Statistics.ProcessCount,
	)

	fmt.Printf(
		"Processes with Network : %d\n",
		result.Statistics.ProcessWithNetwork,
	)

	fmt.Printf(
		"Connections            : %d\n",
		result.Statistics.ConnectionCount,
	)

	fmt.Printf(
		"TCP                    : %d\n",
		result.Statistics.TCPCount,
	)

	fmt.Printf(
		"UDP                    : %d\n",
		result.Statistics.UDPCount,
	)

	fmt.Printf(
		"Listeners              : %d\n",
		result.Statistics.ListenerCount,
	)

	fmt.Printf(
		"External Connections   : %d\n",
		result.Statistics.ExternalConnectionCount,
	)

	fmt.Printf(
		"Processes with Indicator: %d\n",
		indicatorProcesses,
	)

	fmt.Printf(
		"Orphan Connections     : %d\n",
		len(
			result.OrphanConnections,
		),
	)

	fmt.Printf(
		"Output                 : %s\n",
		outputFile,
	)

	fmt.Println()
	fmt.Printf(
		"Process Relationships  : %d\n",
		relationshipResult.Statistics.ParentChildRelations,
	)

	fmt.Printf(
		"Relationship Findings  : %d\n",
		relationshipResult.Statistics.Findings,
	)

	fmt.Printf(
		"Relationship Output    : %s\n",
		relationshipOutputFile,
	)

	fmt.Println()

	fmt.Println(
		"Persistence Analysis",
	)

	fmt.Printf(
		"Services               : %d\n",
		persistenceResult.Statistics.ServiceCount,
	)

	fmt.Printf(
		"Run Keys               : %d\n",
		persistenceResult.Statistics.RunKeyCount,
	)

	fmt.Printf(
		"Scheduled Tasks        : %d\n",
		persistenceResult.Statistics.ScheduledTaskCount,
	)

	fmt.Printf(
		"Persistence Findings   : %d\n",
		persistenceResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		persistenceResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		persistenceResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		persistenceResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"Persistence Output     : %s\n",
		persistenceOutputFile,
	)

	fmt.Println()

	fmt.Println(
		"Login Analysis",
	)

	fmt.Printf(
		"Login Sessions         : %d\n",
		loginResult.Statistics.SessionCount,
	)

	fmt.Printf(
		"RDP Sessions           : %d\n",
		loginResult.Statistics.RemoteInteractiveCount,
	)

	fmt.Printf(
		"Network Logons         : %d\n",
		loginResult.Statistics.NetworkLogonCount,
	)

	fmt.Printf(
		"Privileged Sessions    : %d\n",
		loginResult.Statistics.PrivilegedSessionCount,
	)

	fmt.Printf(
		"Explicit Credentials   : %d\n",
		loginResult.Statistics.ExplicitCredentialCount,
	)

	fmt.Printf(
		"Failed Logons          : %d\n",
		loginResult.Statistics.FailedLoginCount,
	)

	fmt.Printf(
		"Login Findings         : %d\n",
		loginResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		loginResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		loginResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		loginResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"Login Output           : %s\n",
		loginOutputFile,
	)

	fmt.Println()

	fmt.Println(
		"Unified Activity Analysis",
	)

	fmt.Printf(
		"Activity Nodes         : %d\n",
		activityResult.Statistics.NodeCount,
	)

	fmt.Printf(
		"Activity Edges         : %d\n",
		activityResult.Statistics.EdgeCount,
	)

	fmt.Printf(
		"Login Nodes            : %d\n",
		activityResult.Statistics.LoginNodeCount,
	)

	fmt.Printf(
		"Process Nodes          : %d\n",
		activityResult.Statistics.ProcessNodeCount,
	)

	fmt.Printf(
		"Network Nodes          : %d\n",
		activityResult.Statistics.NetworkNodeCount,
	)

	fmt.Printf(
		"Persistence Nodes      : %d\n",
		activityResult.Statistics.PersistenceNodeCount,
	)

	fmt.Printf(
		"Attack Chains          : %d\n",
		activityResult.Statistics.AttackChainCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		activityResult.Statistics.CriticalChainCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		activityResult.Statistics.HighChainCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		activityResult.Statistics.MediumChainCount,
	)

	fmt.Printf(
		"Activity Output        : %s\n",
		activityOutputFile,
	)

	fmt.Println()

	fmt.Println(
		"Timeline",
	)

	fmt.Printf(
		"Timeline Events        : %d\n",
		timelineResult.Statistics.EventCount,
	)

	fmt.Printf(
		"  Login               : %d\n",
		timelineResult.Statistics.LoginEvents,
	)

	fmt.Printf(
		"  Process             : %d\n",
		timelineResult.Statistics.ProcessEvents,
	)

	fmt.Printf(
		"  Network             : %d\n",
		timelineResult.Statistics.NetworkEvents,
	)

	fmt.Printf(
		"  Persistence         : %d\n",
		timelineResult.Statistics.PersistenceEvents,
	)

	fmt.Printf(
		"  Historical Process  : %d\n",
		timelineResult.Statistics.HistoricalProcessEvents,
	)

	fmt.Printf(
		"  PowerShell          : %d\n",
		timelineResult.Statistics.PowerShellEvents,
	)

	fmt.Printf(
		"Timeline JSON         : %s\n",
		timelineJSONFile,
	)

	fmt.Printf(
		"Timeline JSONL        : %s\n",
		timelineJSONLFile,
	)

	fmt.Println()

	fmt.Println(
		"File Analysis",
	)

	fmt.Printf(
		"Files                  : %d\n",
		fileResult.Statistics.FileCount,
	)

	fmt.Printf(
		"Executables/Scripts    : %d\n",
		fileResult.Statistics.ExecutableCount,
	)

	fmt.Printf(
		"Observed Executed      : %d\n",
		fileResult.Statistics.ExecutedFileCount,
	)

	fmt.Printf(
		"Persistence Referenced : %d\n",
		fileResult.Statistics.PersistenceReferencedCount,
	)

	fmt.Printf(
		"File Findings          : %d\n",
		fileResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		fileResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		fileResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		fileResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"File Output            : %s\n",
		fileAnalysisOutput,
	)

	fmt.Println()

	fmt.Println(
		"Historical Process Analysis",
	)

	fmt.Printf(
		"Process Events         : %d\n",
		processHistoryResult.Statistics.EventCount,
	)

	fmt.Printf(
		"Historical Processes   : %d\n",
		processHistoryResult.Statistics.HistoricalProcessCount,
	)

	fmt.Printf(
		"Parent/Child Edges     : %d\n",
		processHistoryResult.Statistics.ParentChildEdgeCount,
	)

	fmt.Printf(
		"Matched Login          : %d\n",
		processHistoryResult.Statistics.MatchedLoginCount,
	)

	fmt.Printf(
		"Matched Current        : %d\n",
		processHistoryResult.Statistics.MatchedCurrentProcessCount,
	)

	fmt.Printf(
		"Historical Findings    : %d\n",
		processHistoryResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		processHistoryResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		processHistoryResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		processHistoryResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"History Output         : %s\n",
		processHistoryOutput,
	)

	fmt.Println()

	fmt.Println(
		"PowerShell Analysis",
	)

	fmt.Printf(
		"Raw Events             : %d\n",
		powerShellResult.Statistics.RawEventCount,
	)

	fmt.Printf(
		"4103 Module Events     : %d\n",
		powerShellResult.Statistics.ModuleEventCount,
	)

	fmt.Printf(
		"4104 Script Events     : %d\n",
		powerShellResult.Statistics.ScriptBlockEventCount,
	)

	fmt.Printf(
		"Script Blocks          : %d\n",
		powerShellResult.Statistics.ScriptBlockCount,
	)

	fmt.Printf(
		"Complete Blocks        : %d\n",
		powerShellResult.Statistics.CompleteScriptBlockCount,
	)

	fmt.Printf(
		"Incomplete Blocks      : %d\n",
		powerShellResult.Statistics.IncompleteScriptBlockCount,
	)

	fmt.Printf(
		"Matched Process        : %d\n",
		powerShellResult.Statistics.MatchedHistoricalProcessCount,
	)

	fmt.Printf(
		"PowerShell Findings    : %d\n",
		powerShellResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		powerShellResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		powerShellResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		powerShellResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"Output                 : %s\n",
		powerShellAnalysisOutput,
	)

	fmt.Println()

	fmt.Println(
		"Evidence Coverage",
	)

	fmt.Printf(
		"Collection Mode        : %s\n",
		capabilities.CollectionMode,
	)

	fmt.Printf(
		"Historical Coverage    : %d%%\n",
		capabilities.HistoricalCoverage,
	)

	fmt.Printf(
		"Snapshot Coverage      : %d%%\n",
		capabilities.SnapshotCoverage,
	)
	fmt.Println()

	fmt.Println(
		"Windows Event Analysis",
	)

	fmt.Printf(
		"Raw Events             : %d\n",
		windowsEventResult.Statistics.RawEventCount,
	)

	fmt.Printf(
		"Activities             : %d\n",
		windowsEventResult.Statistics.ActivityCount,
	)

	fmt.Printf(
		"  Scheduled Task       : %d\n",
		windowsEventResult.Statistics.TaskActivityCount,
	)

	fmt.Printf(
		"  WMI                  : %d\n",
		windowsEventResult.Statistics.WMIActivityCount,
	)

	fmt.Printf(
		"  Terminal Services    : %d\n",
		windowsEventResult.Statistics.TerminalServicesActivityCount,
	)

	fmt.Printf(
		"Findings               : %d\n",
		windowsEventResult.Statistics.FindingCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		windowsEventResult.Statistics.CriticalCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		windowsEventResult.Statistics.HighCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		windowsEventResult.Statistics.MediumCount,
	)

	fmt.Printf(
		"Output                 : %s\n",
		windowsEventAnalysisOutput,
	)

	fmt.Println()

	fmt.Println(
		"Historical Correlation",
	)

	fmt.Printf(
		"Nodes                  : %d\n",
		historicalCorrelationResult.Statistics.NodeCount,
	)

	fmt.Printf(
		"Edges                  : %d\n",
		historicalCorrelationResult.Statistics.EdgeCount,
	)

	fmt.Printf(
		"  High Confidence      : %d\n",
		historicalCorrelationResult.Statistics.HighConfidenceEdgeCount,
	)

	fmt.Printf(
		"  Medium Confidence    : %d\n",
		historicalCorrelationResult.Statistics.MediumConfidenceEdgeCount,
	)

	fmt.Printf(
		"  Low Confidence       : %d\n",
		historicalCorrelationResult.Statistics.LowConfidenceEdgeCount,
	)

	fmt.Printf(
		"Historical Chains      : %d\n",
		historicalCorrelationResult.Statistics.ChainCount,
	)

	fmt.Printf(
		"  Critical             : %d\n",
		historicalCorrelationResult.Statistics.CriticalChainCount,
	)

	fmt.Printf(
		"  High                 : %d\n",
		historicalCorrelationResult.Statistics.HighChainCount,
	)

	fmt.Printf(
		"  Medium               : %d\n",
		historicalCorrelationResult.Statistics.MediumChainCount,
	)

	fmt.Printf(
		"Output                 : %s\n",
		historicalCorrelationOutput,
	)

	fmt.Println()

	fmt.Println(
		"Case Report",
	)

	fmt.Printf(
		"Overall Severity       : %s\n",
		caseReport.Summary.OverallSeverity,
	)

	fmt.Printf(
		"Risk Score             : %d\n",
		caseReport.Summary.RiskScore,
	)

	fmt.Printf(
		"Top Findings           : %d\n",
		caseReport.Summary.TopFindingCount,
	)

	fmt.Printf(
		"Historical Chains      : %d\n",
		caseReport.Summary.HistoricalChainCount,
	)

	fmt.Printf(
		"Evidence Gaps          : %d\n",
		len(caseReport.EvidenceGaps),
	)

	fmt.Printf(
		"JSON                   : %s\n",
		reportJSONOutput,
	)

	fmt.Printf(
		"Text                   : %s\n",
		reportTextOutput,
	)

	return nil
}
