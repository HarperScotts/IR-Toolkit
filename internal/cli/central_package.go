package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/packageio"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
)

func init() { rootCmd.AddCommand(newCentralImportPackageCommand()) }

func newCentralImportPackageCommand() *cobra.Command {
	var repository, caseID, tempParent string
	cmd := &cobra.Command{
		Use:   "central-import-package --repository <dir> --case-id <id> --temp-parent <private-dir> <package.ircase.tar>",
		Short: "Validate and atomically commit one offline package to an explicit investigation",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			result, err := importPackageFile(ctx, args[0], repository, caseID, tempParent)
			if result.Status != "" {
				if reportErr := json.NewEncoder(cmd.OutOrStdout()).Encode(result); reportErr != nil {
					err = errors.Join(err, fmt.Errorf("import outcome %q; receipt failed, verify repository: %w", result.Status, reportErr))
				}
			}
			return err
		},
	}
	cmd.Flags().StringVar(&repository, "repository", "", "explicit trusted archive destination")
	cmd.Flags().StringVar(&caseID, "case-id", "", "explicit receiving investigation ID (not taken from the package)")
	cmd.Flags().StringVar(&tempParent, "temp-parent", "", "existing private temporary parent with restricted permissions/ACLs")
	for _, flag := range []string{"repository", "case-id", "temp-parent"} {
		_ = cmd.MarkFlagRequired(flag)
	}
	return cmd
}

type packageImportReceipt struct {
	Status        string         `json:"status"`
	View          store.CaseView `json:"view"`
	CaseName      string         `json:"case_name"`
	ContentDigest string         `json:"content_digest"`
	// nil means Commit returned an error and its publication state needs checking.
	Committed *bool `json:"committed"`
}

func importPackageFile(ctx context.Context, input, repository, caseID, tempParent string) (result packageImportReceipt, err error) {
	return importPackageFileWithHooks(ctx, input, repository, caseID, tempParent, packageImportHooks{})
}

// Private fault-injection seam for child-process tests only. Production commands
// pass zero hooks; no CLI flag or runtime environment variable enables them.
type packageImportHooks struct {
	checkpoint func(string)
	reader     func(io.Reader) io.Reader
}

func (h packageImportHooks) at(phase string) {
	if h.checkpoint != nil {
		h.checkpoint(phase)
	}
}

func importPackageFileWithHooks(ctx context.Context, input, repository, caseID, tempParent string, hooks packageImportHooks) (result packageImportReceipt, err error) {
	caseID = strings.TrimSpace(caseID)
	if ctx == nil || input == "" || strings.TrimSpace(repository) == "" || caseID == "" || tempParent == "" {
		return result, fmt.Errorf("context, package, repository, case-id and private temporary parent required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	info, err := os.Lstat(input)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("package input must be a regular non-symlink file")
	}
	if info.Size() > packageio.DefaultLimits().ContainerBytes {
		return result, packageio.ErrLimitExceeded
	}
	file, err := os.Open(input)
	if err != nil {
		return result, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return result, errors.Join(packageio.ErrSourceChanged, statErr, file.Close())
	}
	var reader io.Reader = file
	if hooks.reader != nil {
		reader = hooks.reader(reader)
	}
	extracted, extractErr := packageio.Extract(ctx, reader, tempParent, packageio.DefaultLimits())
	closeErr := file.Close()
	if extracted != nil {
		defer func() {
			if cleanupErr := extracted.Close(); cleanupErr != nil {
				status := result.Status
				if status == "" {
					status = "not-submitted"
				}
				err = errors.Join(err, fmt.Errorf("import outcome %q; temporary cleanup failed: %w", status, cleanupErr))
			}
		}()
	}
	if err := errors.Join(extractErr, closeErr); err != nil {
		return result, err
	}
	hooks.at("extracted")
	if err := rejectRepositoryInsideExtraction(repository, filepath.Dir(extracted.CaseDir())); err != nil {
		return result, err
	}
	metadata := extracted.Verification.Metadata
	view := store.CaseView{CaseID: caseID, HostID: metadata.HostID, Version: metadata.Version}
	loaded, err := loadCentralView(caseID, extracted.CaseDir())
	if err != nil {
		return result, err
	}
	if loaded.View != view {
		return result, packageio.ErrSourceIdentity
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	hooks.at("validated")
	loader := func(current store.CaseView, dir string) (store.CaseStore, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, err := loadArchivedSnapshot(current, dir)
		if err == nil && current == view && strings.HasPrefix(filepath.Base(filepath.Dir(filepath.Dir(dir))), ".stage-") {
			hooks.at("staged")
		}
		return snapshot, err
	}
	// Once Commit starts, cancellation is cooperative at loader boundaries,
	// not a rollback promise. Rename may publish before an error is reported.
	if err := archive.Commit(repository, []archive.Source{{View: view, Dir: extracted.CaseDir(), Name: metadata.CaseName}}, loader); err != nil {
		return packageImportReceipt{Status: "commit-outcome-unknown", View: view, CaseName: metadata.CaseName, ContentDigest: metadata.ContentDigest},
			fmt.Errorf("archive commit returned an error; verify repository before retrying: %w", err)
	}
	hooks.at("published")
	committed := true
	return packageImportReceipt{Status: "committed", View: view, CaseName: metadata.CaseName, ContentDigest: metadata.ContentDigest, Committed: &committed}, nil
}

// The archive guards against destinations inside source case/. Guard the whole
// temporary root too, including sibling paths, so cleanup cannot remove a commit.
func rejectRepositoryInsideExtraction(repository, root string) error {
	rootInfo, err := os.Stat(root)
	if err != nil {
		return err
	}
	current, err := filepath.Abs(repository)
	if err != nil {
		return err
	}
	for {
		_, err := os.Lstat(current)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return err
		}
		current = parent
	}
	current, err = filepath.EvalSymlinks(current)
	if err != nil {
		return err
	}
	for {
		info, err := os.Stat(current)
		if err != nil {
			return err
		}
		if os.SameFile(rootInfo, info) {
			return fmt.Errorf("repository must be outside the entire temporary extraction root")
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}
