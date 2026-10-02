package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show tool and runtime information",

	Run: func(
		cmd *cobra.Command,
		args []string,
	) {

		fmt.Println(
			"========================================",
		)

		fmt.Println(
			"          IR Toolkit",
		)

		fmt.Println(
			"          Incident Response",
		)

		fmt.Println(
			"========================================",
		)

		fmt.Printf(
			"OS           : %s\n",
			runtime.GOOS,
		)

		fmt.Printf(
			"Architecture : %s\n",
			runtime.GOARCH,
		)

		fmt.Printf(
			"Go Version   : %s\n",
			runtime.Version(),
		)
	},
}
