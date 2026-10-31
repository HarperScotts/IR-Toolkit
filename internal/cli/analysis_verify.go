package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/analysiscommit"
)

func newAnalysisVerifyCommand() *cobra.Command {
	return &cobra.Command{Use: "analysis-verify <case-dir>", Short: "Read-only analysis completion inventory check (not domain loading/publication attestation)", Args: cobra.ExactArgs(1), SilenceUsage: true, RunE: func(cmd *cobra.Command, args []string) error {
		verified, err := analysiscommit.VerifyDirectory(cmd.Context(), args[0], analysiscommit.DefaultLimits())
		status := "legacy_unmanaged"
		if err != nil {
			status = "rejected"
		} else if verified.Managed {
			status = "inventory_verified"
		}
		receipt := map[string]any{"status": status, "domains_loaded": false, "publication_attested": false, "scope": "Byte inventory consistency only; no domain validation, authenticity or atomic publication guarantee. Legacy means both markers absent, not protocol completion."}
		if err == nil {
			receipt["managed"] = verified.Managed
		}
		if verified.Managed {
			receipt["file_count"] = verified.FileCount
			receipt["payload_bytes"] = verified.PayloadBytes
			receipt["run_id"] = verified.Run.RunID
			receipt["content_digest"] = verified.Commit.ContentDigest
		}
		if err != nil {
			receipt["error"] = err.Error()
		}
		if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(receipt); writeErr != nil {
			return writeErr
		}
		if err != nil {
			return fmt.Errorf("analysis inventory verification failed: %w", err)
		}
		return nil
	}}
}

func init() { rootCmd.AddCommand(newAnalysisVerifyCommand()) }
