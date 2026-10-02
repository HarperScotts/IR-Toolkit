package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"

	"github.com/spf13/cobra"
)

var treeFile string

var treeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Build process tree from collected process evidence",
	RunE:  runTree,
}

func init() {

	treeCmd.Flags().StringVarP(
		&treeFile,
		"file",
		"f",
		"",
		"processes.json",
	)

	rootCmd.AddCommand(treeCmd)
}

func runTree(
	cmd *cobra.Command,
	args []string,
) error {

	if treeFile == "" {
		return fmt.Errorf(
			"please specify --file",
		)
	}

	data, err := os.ReadFile(
		treeFile,
	)

	if err != nil {
		return err
	}

	var processes []model.Process

	if err := json.Unmarshal(
		data,
		&processes,
	); err != nil {
		return fmt.Errorf(
			"parse process evidence: %w",
			err,
		)
	}

	tree := analyzer.BuildProcessTree(
		processes,
	)

	output, err := json.MarshalIndent(
		tree,
		"",
		"  ",
	)

	if err != nil {
		return err
	}

	fmt.Println(
		string(output),
	)

	return nil
}
