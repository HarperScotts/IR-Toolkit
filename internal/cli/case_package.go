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
	"reflect"
	"syscall"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/packageio"
)

func init() {
	rootCmd.AddCommand(newCasePackCommand(), newCaseVerifyCommand())
}

func newCasePackCommand() *cobra.Command {
	var output string
	cmd := &cobra.Command{
		Use:   "case-pack <complete-case-dir> --output <new-package.ircase.tar>",
		Short: "Export a stopped, complete local case without overwriting any output",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			result, err := packCaseFile(ctx, args[0], output)
			if err != nil {
				return err
			}
			// A reporting error does not remove a successfully completed package.
			if err := writePackageReceipt(cmd.OutOrStdout(), "exported", result, true); err != nil {
				return fmt.Errorf("package completed at %q, but receipt failed: %w", output, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&output, "output", "", "new output file outside the source tree (parent must exist)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func newCaseVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "case-verify <package.ircase.tar>",
		Short: "Read-only framing, inventory and source-identity verification (not domain loading or import)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			result, err := verifyCaseFile(ctx, args[0])
			if err != nil {
				return err
			}
			return writePackageReceipt(cmd.OutOrStdout(), "verified-framing-source", result, false)
		},
	}
}

type packageReceipt struct {
	Status         string `json:"status"`
	HostID         string `json:"host_id"`
	Version        string `json:"version"`
	CaseName       string `json:"case_name"`
	ContentDigest  string `json:"content_digest"`
	FileCount      int    `json:"file_count"`
	PayloadBytes   int64  `json:"payload_bytes"`
	ContainerBytes int64  `json:"container_bytes"`
	DomainsLoaded  bool   `json:"domains_loaded"`
	Committed      bool   `json:"committed"`
}

func writePackageReceipt(writer io.Writer, status string, result packageio.ContainerVerification, domains bool) error {
	return json.NewEncoder(writer).Encode(packageReceipt{
		Status: status, HostID: result.Metadata.HostID, Version: result.Metadata.Version,
		CaseName: result.Metadata.CaseName, ContentDigest: result.Metadata.ContentDigest,
		FileCount: len(result.Metadata.Files), PayloadBytes: result.PayloadBytes,
		ContainerBytes: result.ContainerBytes, DomainsLoaded: domains, Committed: false,
	})
}

// packCaseFile requires trusted, stopped source and output-parent directories.
// Exclusive creation prevents overwrites, not observation of an in-progress
// file. Only success after validation, Sync and Close marks a completed package.
func packCaseFile(ctx context.Context, source, destination string) (result packageio.ContainerVerification, err error) {
	return packCaseFileWithHooks(ctx, source, destination, packagePackHooks{})
}

// Private test seam, with no production CLI/environment switches.
type packagePackHooks struct {
	writer     func(io.Writer) io.Writer
	checkpoint func(string)
}

func packCaseFileWithHooks(ctx context.Context, source, destination string, hooks packagePackHooks) (result packageio.ContainerVerification, err error) {
	if ctx == nil || source == "" || destination == "" {
		return result, fmt.Errorf("context, source and output are required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	root, output, err := resolvePackagePaths(source, destination)
	if err != nil {
		return result, err
	}
	file, err := os.OpenFile(output, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, fmt.Errorf("create new output: %w", err)
	}
	owned, statErr := file.Stat()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if err != nil {
			// Never delete a path replaced by somebody else, even in this trusted
			// parent. A process kill can leave a partial file; no automatic recovery.
			err = errors.Join(err, removeOwnedPackage(output, owned))
			result = packageio.ContainerVerification{}
		}
	}()
	if statErr != nil {
		return result, statErr
	}
	limits := packageio.DefaultLimits()
	var writer io.Writer = file
	if hooks.writer != nil {
		writer = hooks.writer(writer)
	}
	result, err = packageio.ExportCase(ctx, root, filepath.Base(root), writer, limits)
	if err != nil {
		return packageio.ContainerVerification{}, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return packageio.ContainerVerification{}, err
	}
	checked, err := packageio.VerifySource(ctx, file, limits)
	if err != nil {
		return packageio.ContainerVerification{}, err
	}
	if !reflect.DeepEqual(checked, result) {
		return packageio.ContainerVerification{}, packageio.ErrPayloadMismatch
	}
	// Reuse the existing full-domain loader after bounded export/verification.
	// This synthetic scope is local only; it is never published or stored in the package.
	loaded, err := loadCentralView("offline-pack-preflight", root)
	if err != nil {
		return packageio.ContainerVerification{}, err
	}
	if loaded.View.HostID != result.Metadata.HostID || loaded.View.Version != result.Metadata.Version {
		return packageio.ContainerVerification{}, packageio.ErrSourceIdentity
	}
	// Domain loading reads the source, not an extracted archive. Re-export to a
	// discard sink to detect source changes between byte validation and loading.
	current, err := packageio.ExportCase(ctx, root, result.Metadata.CaseName, io.Discard, limits)
	if err != nil {
		return packageio.ContainerVerification{}, err
	}
	if current.Metadata.ContentDigest != result.Metadata.ContentDigest {
		return packageio.ContainerVerification{}, packageio.ErrSourceChanged
	}
	if err := ctx.Err(); err != nil {
		return packageio.ContainerVerification{}, err
	}
	if err := file.Sync(); err != nil {
		return packageio.ContainerVerification{}, err
	}
	err = file.Close()
	closed = true
	if err != nil {
		return packageio.ContainerVerification{}, err
	}
	if err := ctx.Err(); err != nil {
		return packageio.ContainerVerification{}, err
	}
	if hooks.checkpoint != nil {
		hooks.checkpoint("completed")
	}
	return result, nil
}

func resolvePackagePaths(source, destination string) (string, string, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return "", "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("source must be a real directory")
	}
	root, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", "", err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	output, err := filepath.Abs(destination)
	if err != nil {
		return "", "", err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return "", "", err
	}
	output = filepath.Join(parent, filepath.Base(output))
	// Physical ancestry also catches parent symlinks and case-only aliases on
	// case-insensitive filesystems; lexical prefix matching is insufficient.
	for ancestor := parent; ; ancestor = filepath.Dir(ancestor) {
		ancestorInfo, err := os.Stat(ancestor)
		if err != nil {
			return "", "", err
		}
		if !ancestorInfo.IsDir() {
			return "", "", fmt.Errorf("output parent is not a directory")
		}
		if os.SameFile(info, ancestorInfo) {
			return "", "", fmt.Errorf("output must be outside the source tree")
		}
		if filepath.Dir(ancestor) == ancestor {
			break
		}
	}
	return root, output, nil
}

func removeOwnedPackage(path string, owned os.FileInfo) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect incomplete output for cleanup: %w", err)
	}
	if owned == nil || !os.SameFile(owned, info) || !info.Mode().IsRegular() {
		return fmt.Errorf("output path changed; not removing %q", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove incomplete output: %w", err)
	}
	return nil
}

func verifyCaseFile(ctx context.Context, path string) (result packageio.ContainerVerification, err error) {
	if ctx == nil || path == "" {
		return result, fmt.Errorf("context and package path required")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() {
		return result, fmt.Errorf("package input must be a regular non-symlink file")
	}
	if info.Size() > packageio.DefaultLimits().ContainerBytes {
		return result, packageio.ErrLimitExceeded
	}
	file, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			result = packageio.ContainerVerification{}
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return result, err
	}
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() {
		return result, packageio.ErrSourceChanged
	}
	result, err = packageio.VerifySource(ctx, file, packageio.DefaultLimits())
	return result, err
}
