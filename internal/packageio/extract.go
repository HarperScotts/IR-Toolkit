package packageio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Extraction owns only its newly created temporary tree. Verification confirms
// container bytes and source consistency, not domain loadability or authenticity.
// Call Close after loading/committing; it removes the temporary data, not input
// packages or repository contents. CaseName is never used as a filesystem path.
type Extraction struct {
	Verification ContainerVerification
	root         string
	rootInfo     os.FileInfo
	caseDir      string
	mu           sync.Mutex
	removed      bool
}

func (e *Extraction) CaseDir() string { return e.caseDir }

// Close is idempotent and refuses to remove a replaced root. It cannot recover
// from process termination; the caller must explicitly handle any orphaned tree.
func (e *Extraction) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.removed {
		return nil
	}
	info, err := os.Lstat(e.root)
	if errors.Is(err, os.ErrNotExist) {
		e.removed = true
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect extraction root %q: %w", e.root, err)
	}
	if e.rootInfo == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(e.rootInfo, info) {
		return fmt.Errorf("extraction root replaced; not removing %q", e.root)
	}
	if err := os.RemoveAll(e.root); err != nil {
		return fmt.Errorf("remove extraction root %q: %w", e.root, err)
	}
	e.removed = true
	return nil
}

// Extract reads one bounded package into a fresh temporary tree under an
// explicitly supplied, existing trusted parent. It never reuses an extraction
// directory. On failure no result is returned and this invocation's tree is
// cleaned up; cleanup failures identify the retained path in the error.
// It does not load domains, authenticate senders, publish views or close reader.
// Trusted parent permissions/ACLs must restrict local access, especially on
// Windows where Go permission bits do not establish a private ACL. This is not a
// defense against attackers concurrently controlling the parent filesystem.
func Extract(ctx context.Context, reader io.Reader, tempParent string, limits Limits) (extraction *Extraction, err error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if ctx == nil || reader == nil || tempParent == "" {
		return nil, fmt.Errorf("context, reader and temporary parent required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	parent, err := filepath.Abs(tempParent)
	if err != nil {
		return nil, err
	}
	parent, err = filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("temporary parent must be an existing directory")
	}
	root, err := os.MkdirTemp(parent, "ir-toolkit-extract-")
	if err != nil {
		return nil, err
	}
	owned := &Extraction{root: root, caseDir: filepath.Join(root, "case")}
	defer func() {
		if err != nil {
			err = errors.Join(err, owned.Close())
			extraction = nil
		}
	}()
	owned.rootInfo, err = os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(root, 0700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(owned.caseDir, 0700); err != nil {
		return nil, err
	}
	owned.Verification, err = verifySource(ctx, reader, limits, func(file File) (io.Writer, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return createExtractedFile(owned.caseDir, file.Path)
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return owned, nil
}

func createExtractedFile(caseDir, path string) (*os.File, error) {
	if err := ValidatePayloadPath(path); err != nil {
		return nil, err
	}
	target := filepath.Join(caseDir, filepath.FromSlash(path))
	relative, err := filepath.Rel(caseDir, target)
	if err != nil || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%w: extraction containment", ErrInvalidPath)
	}
	// Build one component at a time and inspect existing components rather
	// than using MkdirAll, which could silently follow a pre-existing link.
	directory := caseDir
	components := strings.Split(path, "/")
	for index := 0; index < len(components); index++ {
		info, err := os.Lstat(directory)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: extraction directory is not a real directory", ErrInvalidPath)
		}
		if index == len(components)-1 {
			break
		}
		directory = filepath.Join(directory, components[index])
		if err := os.Mkdir(directory, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
