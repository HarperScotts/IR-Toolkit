// Package archive persists complete case directories without rewriting evidence.
package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/central"
)

var ErrWriterBusy = errors.New("archive writer lock exists; verify no writer is running before recovering the lock")

type Loader func(view store.CaseView, dir string) (store.CaseStore, error)

type Source struct {
	View store.CaseView
	Dir  string
	// Name is display-only. Empty retains the existing directory-basename default.
	Name string
}

type Entry struct {
	View store.CaseView `json:"view"`
	Name string         `json:"name"`
	Dir  string         `json:"dir"`
}

type commit struct {
	Version int               `json:"version"`
	Entries []Entry           `json:"entries"`
	Files   map[string]string `json:"files"`
}

type namedStore struct {
	store.CaseStore
	name string
}

func (s *namedStore) CaseName() string { return s.name }

// Load verifies every committed batch before returning any views. Staging
// directories are ignored, never automatically deleted. The repository must
// be a trusted local directory, not an untrusted remotely writable tree.
func Load(root string, loader Loader) (*central.Repository, []Entry, error) {
	if loader == nil {
		return nil, nil, errors.New("archive loader is required")
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("archive root must be a regular directory")
	}
	items, err := os.ReadDir(root)
	if err != nil {
		return nil, nil, err
	}
	repository, _ := central.NewRepository()
	var entries []Entry
	for _, item := range items {
		if strings.HasPrefix(item.Name(), ".stage-") || item.Name() == ".ingest.lock" {
			continue
		}
		if !strings.HasPrefix(item.Name(), "batch-") || !item.IsDir() || item.Type()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("unexpected archive entry %q", item.Name())
		}
		batchDir := filepath.Join(root, item.Name())
		info, err := os.Lstat(filepath.Join(batchDir, "commit.json"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, nil, errors.New("archive commit must be a regular file")
		}
		data, err := os.ReadFile(filepath.Join(batchDir, "commit.json"))
		if err != nil {
			return nil, nil, err
		}
		var manifest commit
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&manifest); err != nil {
			return nil, nil, err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, nil, errors.New("trailing archive commit data")
		}
		if manifest.Version != 1 || len(manifest.Entries) == 0 || manifest.Files == nil {
			return nil, nil, errors.New("invalid archive commit format/version")
		}
		files, err := inventory(filepath.Join(batchDir, "cases"), nil)
		if err != nil {
			return nil, nil, err
		}
		if len(files) != len(manifest.Files) {
			return nil, nil, errors.New("archive file inventory mismatch")
		}
		for path, digest := range files {
			if manifest.Files[path] != digest {
				return nil, nil, fmt.Errorf("archive checksum mismatch: %s", path)
			}
		}
		requests := make([]central.IngestRequest, 0, len(manifest.Entries))
		for index, entry := range manifest.Entries {
			if !entry.View.Valid() || entry.Dir != fmt.Sprintf("%06d", index) || entry.Name == "" {
				return nil, nil, errors.New("invalid archive view/directory")
			}
			entry.Dir = filepath.Join(batchDir, "cases", entry.Dir)
			snapshot, err := loader(entry.View, entry.Dir)
			if err != nil {
				return nil, nil, fmt.Errorf("load archive view %+v: %w", entry.View, err)
			}
			if _, err := central.New(entry.View, snapshot); err != nil {
				return nil, nil, err
			}
			requests = append(requests, central.IngestRequest{View: entry.View, Snapshot: &namedStore{CaseStore: snapshot, name: entry.Name}})
			entries = append(entries, entry)
		}
		if _, err := repository.IngestBatch(requests...); err != nil {
			return nil, nil, err
		}
	}
	return repository, entries, nil
}

// Commit copies and validates an entire batch, then publishes it by directory
// rename on the same filesystem. Sources must be complete and quiescent. This
// guarantees atomic visibility, not power-loss durability on every filesystem.
// A crashed writer's lock requires explicit operator recovery.
func Commit(root string, sources []Source, loader Loader) (err error) {
	return commitBatch(root, sources, loader, nil)
}

// checkpoint is a private fault-injection seam for subprocess tests. Public
// callers never install it; there are no runtime environment-controlled hooks.
func commitBatch(root string, sources []Source, loader Loader, checkpoint func(string)) (err error) {
	if len(sources) == 0 || loader == nil {
		return errors.New("archive sources and loader are required")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	resolvedRoot, err := resolveExistingParents(root)
	if err != nil {
		return err
	}
	for _, source := range sources {
		absolute, err := filepath.Abs(source.Dir)
		if err != nil {
			return err
		}
		resolvedSource, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(resolvedSource, resolvedRoot)
		if err != nil || relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))) {
			return errors.New("archive destination must not be inside a source case")
		}
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	lockPath := filepath.Join(root, ".ingest.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrWriterBusy
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.Remove(lockPath)) }()
	if err := lock.Close(); err != nil {
		return err
	}
	repository, _, err := Load(root, loader)
	if err != nil {
		return err
	}
	seen := map[store.CaseView]bool{}
	for _, source := range sources {
		if !source.View.Valid() {
			return store.ErrInvalidCaseView
		}
		if _, exists := repository.Open(source.View); exists || seen[source.View] {
			return central.ErrDuplicateView
		}
		seen[source.View] = true
	}
	stage, err := os.MkdirTemp(root, ".stage-")
	if err != nil {
		return err
	}
	// Only this invocation's newly created staging directory is removed on error.
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(stage))
		}
	}()
	manifest := commit{Version: 1, Files: map[string]string{}}
	for index, source := range sources {
		name := fmt.Sprintf("%06d", index)
		destination := filepath.Join(stage, "cases", name)
		files, err := inventory(source.Dir, &destination)
		if err != nil {
			return err
		}
		snapshot, err := loader(source.View, destination)
		if err != nil {
			return fmt.Errorf("validate staged view %+v: %w", source.View, err)
		}
		if _, err := central.New(source.View, snapshot); err != nil {
			return err
		}
		caseName := source.Name
		if caseName == "" {
			caseName = filepath.Base(filepath.Clean(source.Dir))
		}
		manifest.Entries = append(manifest.Entries, Entry{View: source.View, Name: caseName, Dir: name})
		for path, digest := range files {
			manifest.Files[name+"/"+path] = digest
		}
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := writeCommit(filepath.Join(stage, "commit.json"), data); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint("staged")
	}
	final := filepath.Join(root, "batch-"+strings.TrimPrefix(filepath.Base(stage), ".stage-"))
	if _, err := os.Lstat(final); !errors.Is(err, os.ErrNotExist) {
		return errors.New("archive batch destination already exists or is inaccessible")
	}
	if err := os.Rename(stage, final); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint("published")
	}
	return nil
}

// Resolve existing parent aliases even when the destination does not exist,
// so e.g. /tmp and /private/tmp cannot bypass the recursive-copy guard.
func resolveExistingParents(path string) (string, error) {
	var suffix []string
	current := path
	for {
		_, err := os.Lstat(current)
		if err == nil {
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return resolved, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func writeCommit(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	return errors.Join(writeErr, syncErr, file.Close())
}

// inventory rejects links and special files and streams regular file bytes.
func inventory(root string, destination *string) (map[string]string, error) {
	return inventoryObserved(root, destination, nil)
}

// Private benchmark seam. Normal calls install no observer and take no timestamps.
func inventoryObserved(root string, destination *string, observe func(string, time.Duration)) (map[string]string, error) {
	files := map[string]string{}
	buffer := make([]byte, 32<<10)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink evidence is not supported: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if destination != nil {
				return os.MkdirAll(filepath.Join(*destination, relative), 0o700)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular evidence is not supported: %s", path)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		digest := sha256.New()
		var writer io.Writer = digest
		var output *os.File
		if destination != nil {
			output, err = os.OpenFile(filepath.Join(*destination, relative), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			writer = io.MultiWriter(digest, output)
		}
		// Hide os.File.WriteTo so CopyBuffer uses this inventory's buffer rather
		// than the generic per-file allocation in the file fast-path fallback.
		var started time.Time
		if observe != nil {
			started = time.Now()
		}
		_, err = io.CopyBuffer(writer, struct{ io.Reader }{input}, buffer)
		if observe != nil {
			observe("copy", time.Since(started))
		}
		if output != nil {
			if observe == nil {
				err = errors.Join(err, output.Sync(), output.Close())
			} else {
				started = time.Now()
				syncErr := output.Sync()
				observe("sync", time.Since(started))
				err = errors.Join(err, syncErr, output.Close())
			}
		}
		if err != nil {
			return err
		}
		files[filepath.ToSlash(relative)] = hex.EncodeToString(digest.Sum(nil))
		return nil
	})
	return files, err
}
