package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	webserver "ir-toolkit/internal/web"
)

var (
	webListen string
)

var webCmd = &cobra.Command{
	Use: "web <case-dir>",

	Short: "Start local web UI for an incident response case",

	Args: cobra.ExactArgs(1),

	RunE: runWeb,
}

func init() {

	webCmd.Flags().
		StringVar(
			&webListen,
			"listen",
			"127.0.0.1:8080",
			"HTTP listen address",
		)

	rootCmd.AddCommand(
		webCmd,
	)
}

func runWeb(
	cmd *cobra.Command,
	args []string,
) error {

	caseDir :=
		args[0]

	server, err :=
		webserver.NewServer(
			webserver.Options{
				CaseDir: caseDir,

				ListenAddr: webListen})

	if err != nil {
		return err
	}

	if webListen !=
		"127.0.0.1:8080" {

		fmt.Println()
		fmt.Println(
			"WARNING:",
		)

		fmt.Println(
			"The web server may expose sensitive incident-response evidence.",
		)

		fmt.Println(
			"Use non-localhost listeners only on trusted networks.",
		)

		fmt.Println()
	}

	ctx, cancel :=
		signal.NotifyContext(
			context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)

	defer cancel()

	fmt.Println(
		"IR-Toolkit Web UI",
	)

	fmt.Printf(
		"Case   : %s\n",
		server.CaseDir(),
	)

	fmt.Printf(
		"Listen : http://%s\n",
		server.ListenAddr(),
	)

	fmt.Println()
	fmt.Println(
		"Press Ctrl+C to stop.",
	)

	return server.Run(
		ctx,
	)
}
