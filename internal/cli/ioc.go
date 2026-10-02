package cli

import (
	"github.com/spf13/cobra"
)

var iocCmd = &cobra.Command{
	Use: "ioc",

	Short: "IOC matching and extraction",
}

func init() {
	rootCmd.AddCommand(
		iocCmd,
	)
}
