package cli

import (
	"context"
	"fmt"
	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/ioc"
	"ir-toolkit/internal/model"
	"path/filepath"

	"github.com/spf13/cobra"
)

var iocFilePath string

var iocScanCmd = &cobra.Command{
	Use: "scan <case-dir>",

	Short: "Scan collected evidence using IOC rules",

	Args: cobra.ExactArgs(1),

	RunE: runIOCScan,
}

func init() {

	iocCmd.AddCommand(
		iocScanCmd,
	)

	iocScanCmd.Flags().
		StringVarP(
			&iocFilePath,
			"file",
			"f",
			"",
			"IOC YAML file",
		)

	_ =
		iocScanCmd.MarkFlagRequired(
			"file",
		)
}

func runIOCScan(
	cmd *cobra.Command,
	args []string,
) error {

	ctx :=
		context.Background()

	caseDir :=
		args[0]

	rules, err :=
		ioc.LoadIOCFile(
			iocFilePath,
		)

	if err != nil {
		return err
	}

	files, err :=
		analyzer.LoadFiles(
			filepath.Join(
				caseDir,
				"files",
				"files.json",
			),
		)

	if err != nil {
		return err
	}

	processes, err :=
		analyzer.LoadProcesses(
			filepath.Join(
				caseDir,
				"process",
				"processes.json",
			),
		)

	if err != nil {
		return err
	}

	connections, err :=
		analyzer.LoadNetworkConnections(
			filepath.Join(
				caseDir,
				"network",
				"network.json",
			),
		)

	if err != nil {
		return err
	}

	persistence, err :=
		analyzer.LoadPersistence(
			filepath.Join(
				caseDir,
				"persistence",
				"persistence.json",
			),
		)

	if err != nil {
		return err
	}

	evidence :=
		ioc.CaseEvidence{
			Files: files,

			Processes: processes,

			Network: model.NetworkSnapshot{
				Connections: connections,
			},

			Persistence: persistence,
		}

	result :=
		ioc.Scan(
			ctx,
			rules,
			evidence,
		)

	output :=
		filepath.Join(
			caseDir,
			"analysis",
			"ioc_matches.json",
		)

	if err :=
		ioc.WriteScanResult(
			output,
			result,
		); err != nil {

		return err
	}

	fmt.Println(
		"IOC Scan",
	)

	fmt.Printf(
		"IOC Rules              : %d\n",
		result.Statistics.IOCCount,
	)

	fmt.Printf(
		"Matches                : %d\n",
		result.Statistics.MatchCount,
	)

	fmt.Printf(
		"  Hash                 : %d\n",
		result.Statistics.HashMatches,
	)

	fmt.Printf(
		"  IP                   : %d\n",
		result.Statistics.IPMatches,
	)

	fmt.Printf(
		"  Domain               : %d\n",
		result.Statistics.DomainMatches,
	)

	fmt.Printf(
		"  Path                 : %d\n",
		result.Statistics.PathMatches,
	)

	fmt.Printf(
		"  Process              : %d\n",
		result.Statistics.ProcessNameMatches,
	)

	fmt.Printf(
		"  Command Line         : %d\n",
		result.Statistics.CommandLineMatches,
	)

	fmt.Printf(
		"Output                 : %s\n",
		output,
	)

	return nil
}
