package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/buildinfo"
)

var rootCmd = &cobra.Command{
	Use:     "ir",
	Short:   "Attack & Defense Incident Response Toolkit",
	Version: buildinfo.Version,
}

func init() {

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(collectCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

func ExitWithError(err error) {

	fmt.Fprintf(
		os.Stderr,
		"Error: %v\n",
		err,
	)

	os.Exit(1)
}
