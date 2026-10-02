package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/collector"
	"ir-toolkit/internal/evidence"
	"ir-toolkit/internal/model"
)

var outputDir string
var fullMode bool

var collectSince string
var collectUntil string

var collectLast string

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Collect host evidence",
	RunE:  runCollect,
}

func init() {

	collectCmd.Flags().StringVarP(
		&outputDir,
		"output",
		"o",
		"",
		"Evidence output directory",
	)

	collectCmd.Flags().BoolVar(
		&fullMode,
		"full",
		false,
		"Run full collection profile",
	)

	collectCmd.Flags().StringVar(
		&collectSince,
		"since",
		"",
		"Collect evidence at or after RFC3339 time",
	)

	collectCmd.Flags().StringVar(
		&collectUntil,
		"until",
		"",
		"Collect evidence at or before RFC3339 time",
	)

	collectCmd.Flags().StringVar(
		&collectLast,
		"last",
		"",
		"Collect evidence from the last duration, e.g. 30m, 6h, 24h",
	)
}

func runCollect(
	cmd *cobra.Command,
	args []string,
) error {

	if outputDir == "" {

		outputDir = fmt.Sprintf(
			"case-%s",
			time.Now().Format(
				"20060102-150405",
			),
		)
	}

	start := time.Now().UTC()

	writer, err := evidence.NewWriter(
		outputDir,
	)

	if err != nil {
		return err
	}

	fmt.Println(
		"========================================",
	)

	fmt.Println(
		"          IR Toolkit",
	)

	fmt.Println(
		"          Evidence Collection",
	)

	fmt.Println(
		"========================================",
	)

	fmt.Printf(
		"Platform : %s/%s\n",
		runtime.GOOS,
		runtime.GOARCH,
	)

	fmt.Printf(
		"Output   : %s\n\n",
		filepath.Clean(outputDir),
	)

	if fullMode {
		fmt.Println("Profile  : full")
	} else {
		fmt.Println("Profile  : fast")
	}

	fmt.Println()

	window, err :=
		parseCollectionTimeWindow(
			collectSince,
			collectUntil,
			collectLast,
		)

	if err != nil {
		return err
	}

	ctx :=
		context.Background()

	ctx =
		collection.WithTimeWindow(
			ctx,
			window,
		)

	// 输出 Since 、Until
	if window.Since != nil {

		fmt.Printf(
			"Since    : %s\n",
			window.Since.
				Format(
					time.RFC3339,
				),
		)
	}

	if window.Until != nil {

		fmt.Printf(
			"Until    : %s\n",
			window.Until.
				Format(
					time.RFC3339,
				),
		)
	}

	if !window.Empty() {
		fmt.Println()
	}

	// host、process、network、persistence、login
	hostCollector, err :=
		collector.NewHostCollector()

	if err != nil {
		return err
	}

	processCollector, err :=
		collector.NewProcessCollector()

	if err != nil {
		return err
	}

	networkCollector, err := collector.NewNetworkCollector()
	if err != nil {
		return err
	}

	persistenceCollector, err :=
		collector.NewPersistenceCollector()

	if err != nil {
		return err
	}

	loginCollector, err :=
		collector.NewLoginCollector()

	if err != nil {
		return err
	}

	fileCollector, err :=
		collector.NewFileCollector()

	if err != nil {
		return err
	}

	processEventCollector, err :=
		collector.NewProcessEventCollector()

	if err != nil {
		return err
	}

	powerShellEventCollector, err :=
		collector.NewPowerShellEventCollector()

	if err != nil {
		return err
	}

	capabilityCollector, err :=
		collector.NewCapabilityCollector()

	if err != nil {
		return err
	}

	securityProviderCollector, err :=
		collector.NewSecurityProviderCollector()

	if err != nil {
		return err
	}

	genericEventCollector, err :=
		collector.NewGenericEventCollector()

	if err != nil {
		return err
	}

	results := collector.Run(
		ctx,
		[]collector.Collector{
			capabilityCollector,
			securityProviderCollector,

			hostCollector,
			processCollector,
			networkCollector,
			persistenceCollector,
			loginCollector,
			fileCollector,
			processEventCollector,
			powerShellEventCollector,
			genericEventCollector,
		},
	)

	manifest := model.Manifest{
		CaseID: filepath.Base(
			filepath.Clean(outputDir),
		),

		ToolVersion: "0.1.0",

		Platform: runtime.GOOS,

		Architecture: runtime.GOARCH,

		StartedAt: start,

		CollectionSince: window.Since,

		CollectionUntil: window.Until,
	}

	for _, result := range results {

		status := "OK"

		if result.Error != "" {
			status = "WARN"
		}

		fmt.Printf(
			"[+] %-24s %s\n",
			result.Name,
			status,
		)

		if result.Error != "" {
			fmt.Printf(
				"    error: %s\n",
				result.Error,
			)
		}

		if result.Data == nil {
			continue
		}

		var relativePath string

		switch result.Name {

		case "windows_capabilities",
			"linux_capabilities":

			relativePath =
				"capabilities/capabilities.json"

		case "windows_security_providers",
			"linux_security_providers":

			relativePath =
				"capabilities/security_providers.json"

		case "linux_host",
			"windows_host":

			relativePath =
				"host/host.json"

		case "linux_process",
			"windows_process":

			relativePath =
				"process/processes.json"

		case "linux_network",
			"windows_network":

			relativePath =
				"network/network.json"

		case "linux_persistence",
			"windows_persistence":

			relativePath =
				"persistence/persistence.json"

		case "linux_login",
			"windows_login":

			relativePath =
				"login/login.json"

		case "linux_files",
			"windows_files":

			relativePath =
				"files/files.json"

		case "windows_process_events",
			"linux_process_events":

			relativePath =
				"events/process_events.json"

		case "windows_powershell_events",
			"linux_powershell_events":

			relativePath =
				"events/powershell_events.json"

		case "windows_generic_events",
			"linux_generic_events":

			relativePath =
				"events/windows_events.json"

		default:

			relativePath =
				"raw/" +
					result.Name +
					".json"
		}

		path, err := writer.WriteJSON(
			relativePath,
			result.Data,
		)

		if err != nil {
			return err
		}

		hash, size, err :=
			evidence.SHA256File(path)

		if err != nil {
			return err
		}

		manifest.Files =
			append(
				manifest.Files,
				model.EvidenceFile{
					Path:   relativePath,
					SHA256: hash,
					Size:   size,
				},
			)
	}

	manifest.FinishedAt =
		time.Now().UTC()

	if _, err := writer.WriteJSON(
		"manifest.json",
		manifest,
	); err != nil {
		return err
	}

	fmt.Println()

	fmt.Printf(
		"Completed in %s\n",
		time.Since(start).Round(
			time.Millisecond,
		),
	)

	printCapabilitySummary(results)
	printSecurityProviderSummary(results)
	printGenericEventSummary(results)

	return nil
}

func printCapabilitySummary(
	results []collector.Result,
) {

	for _, result := range results {

		if result.Name !=
			"windows_capabilities" {

			continue
		}

		capabilities, ok :=
			result.Data.(model.AuditCapabilitySnapshot)

		if !ok {
			return
		}

		fmt.Println()
		fmt.Println(
			"Evidence Capabilities",
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

		fmt.Printf(
			"Security Log           : %s\n",
			capabilities.SecurityLog.Status,
		)

		fmt.Printf(
			"Logon Audit            : %s\n",
			capabilities.LogonAudit.Status,
		)

		fmt.Printf(
			"Process Creation Audit : %s\n",
			capabilities.ProcessCreationAudit.Status,
		)

		fmt.Printf(
			"PowerShell 4104        : %s\n",
			capabilities.PowerShellScriptBlockLogging.Status,
		)

		fmt.Printf(
			"Defender Operational   : %s\n",
			capabilities.DefenderOperational.Status,
		)

		fmt.Printf(
			"Sysmon                 : %s\n",
			capabilities.Sysmon.Status,
		)

		if !capabilities.
			ProcessCreationAudit.
			Enabled {

			fmt.Println(
				"Note: 4688 process history coverage unavailable because process creation auditing was disabled.",
			)
		}

		if !capabilities.
			PowerShellScriptBlockLogging.
			Enabled {

			fmt.Println(
				"Note: PowerShell 4104 coverage unavailable because Script Block Logging was disabled.",
			)
		}

		return
	}
}

func printSecurityProviderSummary(
	results []collector.Result,
) {

	for _, result := range results {

		if result.Name !=
			"windows_security_providers" {

			continue
		}

		value, ok :=
			result.Data.(model.SecurityProviderSnapshot)

		if !ok {
			return
		}

		fmt.Println()
		fmt.Println(
			"Security Providers",
		)

		fmt.Printf(
			"Providers              : %d\n",
			value.Statistics.ProviderCount,
		)

		fmt.Printf(
			"Antivirus              : %d\n",
			value.Statistics.AntivirusCount,
		)

		fmt.Printf(
			"Security Services      : %d\n",
			value.Statistics.SecurityServiceCount,
		)

		fmt.Printf(
			"Useful Event Channels  : %d\n",
			value.Statistics.EventChannelCount,
		)

		for _, provider := range value.Providers {

			fmt.Printf(
				"  %-24s %s\n",
				provider.Name,
				provider.Type,
			)
		}

		return
	}
}

func printGenericEventSummary(
	results []collector.Result,
) {

	for _, result := range results {

		if result.Name !=
			"windows_generic_events" {

			continue
		}

		value, ok :=
			result.Data.(model.WindowsEventSnapshot)

		if !ok {
			return
		}

		fmt.Println()
		fmt.Println(
			"Generic Windows Events",
		)

		fmt.Printf(
			"Definitions            : %d\n",
			value.Statistics.DefinitionCount,
		)

		fmt.Printf(
			"Events                 : %d\n",
			value.Statistics.EventCount,
		)

		for _, definition := range value.Definitions {

			fmt.Printf(
				"  %-20s %-12s %d\n",
				definition.ID,
				definition.Status,
				definition.EventCount,
			)
		}

		return
	}
}
