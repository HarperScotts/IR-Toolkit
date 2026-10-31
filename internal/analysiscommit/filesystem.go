package analysiscommit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrIncomplete = errors.New("incomplete analysis marker pair")
	ErrInventory  = errors.New("analysis inventory mismatch")
	ErrChanged    = errors.New("analysis source changed during verification")
)

// Verification establishes bounded byte inventory consistency only. It does
// not load domains, authenticate identities or attest safe publication.
type Verification struct {
	Managed      bool
	Run          Run
	Commit       Commit
	FileCount    int
	PayloadBytes int64
}

type diskFile struct {
	file File
	info os.FileInfo
}

func sameDiskFile(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func readDiskFile(ctx context.Context, root *os.Root, name string, maximum int64, keep bool) (data []byte, record diskFile, resultErr error) {
	if err := ctx.Err(); err != nil {
		return nil, record, err
	}
	before, err := root.Lstat(name)
	if err != nil {
		return nil, record, err
	}
	if !before.Mode().IsRegular() {
		return nil, record, fmt.Errorf("%w: non-regular file %s", ErrInventory, name)
	}
	if before.Size() < 0 || before.Size() > maximum {
		return nil, record, ErrLimit
	}
	file, err := openVerificationFile(root, name)
	if err != nil {
		return nil, record, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, file.Close())
		if resultErr != nil {
			data = nil
			record = diskFile{}
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, record, err
	}
	if !sameDiskFile(before, opened) {
		return nil, record, ErrChanged
	}
	if err := checkVerificationLinks(file, opened); err != nil {
		return nil, record, err
	}
	hash := sha256.New()
	var total int64
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, record, err
		}
		n, readErr := file.Read(buffer[:min(int64(len(buffer)), maximum-total+1)])
		if n > 0 {
			total += int64(n)
			if total > maximum {
				return nil, record, ErrLimit
			}
			_, _ = hash.Write(buffer[:n])
			if keep {
				data = append(data, buffer[:n]...)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, record, readErr
		}
		if n == 0 {
			return nil, record, io.ErrNoProgress
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, record, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, record, err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return nil, record, errors.Join(ErrChanged, err)
	}
	if !sameDiskFile(before, after) || !sameDiskFile(before, current) || total != before.Size() {
		return nil, record, ErrChanged
	}
	if err := checkVerificationLinks(file, after); err != nil {
		return nil, record, err
	}
	return data, diskFile{File{Path: name, Size: total, SHA256: fmt.Sprintf("%x", hash.Sum(nil))}, current}, nil
}

func markerPresence(ctx context.Context, root *os.Root, limits Limits) (run, commit bool, resultErr error) {
	dir, err := root.Open(".")
	if err != nil {
		return false, false, err
	}
	defer func() { resultErr = errors.Join(resultErr, dir.Close()) }()
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return false, false, err
		}
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > limits.FileCount {
				return false, false, ErrLimit
			}
			name := entry.Name()
			portableName := strings.TrimRight(name, ". ")
			if strings.EqualFold(portableName, RunPath) || strings.EqualFold(portableName, CommitPath) {
				if name != RunPath && name != CommitPath {
					return false, false, fmt.Errorf("%w: non-canonical marker name", ErrInvalid)
				}
				if name == RunPath {
					run = true
				} else {
					commit = true
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return false, false, readErr
		}
	}
	return run, commit, nil
}

// VerifyDirectory requires a trusted local parent and a stopped source.
// Handle pinning and before/after checks reject observed changes; they do not
// provide an atomic snapshot against a hostile concurrently rewriting host.
// A zero Verification is returned on every error. Neither marker => legacy.
func VerifyDirectory(ctx context.Context, directory string, limits Limits) (result Verification, resultErr error) {
	if err := limits.validate(); err != nil {
		return result, err
	}
	if ctx == nil {
		return result, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	directory = filepath.Clean(directory)
	before, err := os.Lstat(directory)
	if err != nil {
		return result, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return result, ErrInventory
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return result, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, root.Close())
		if resultErr != nil {
			result = Verification{}
		}
	}()
	pinned, err := root.Stat(".")
	if err != nil {
		return result, err
	}
	if !os.SameFile(before, pinned) {
		return result, ErrChanged
	}
	runPresent, commitPresent, err := markerPresence(ctx, root, limits)
	if err != nil {
		return result, err
	}
	if !runPresent && !commitPresent {
		return result, nil
	}
	if !runPresent || !commitPresent {
		return result, ErrIncomplete
	}
	runBytes, runDisk, err := readDiskFile(ctx, root, RunPath, min(limits.MetadataBytes, limits.FileBytes, limits.PayloadBytes), true)
	if err != nil {
		return result, err
	}
	commitBytes, commitDisk, err := readDiskFile(ctx, root, CommitPath, min(limits.MetadataBytes, limits.FileBytes, limits.PayloadBytes-int64(len(runBytes))), true)
	if err != nil {
		return result, err
	}
	run, err := ReadRun(bytes.NewReader(runBytes), limits)
	if err != nil {
		return result, err
	}
	commit, err := ReadCommit(bytes.NewReader(commitBytes), limits)
	if err != nil {
		return result, err
	}
	if err := ValidatePair(run, commit, limits); err != nil {
		return result, err
	}
	expected := map[string]File{CommitPath: commitDisk.file}
	directories := map[string]bool{"": true}
	for _, file := range commit.Files {
		expected[file.Path] = file
		parts := strings.Split(file.Path, "/")
		for n := 1; n < len(parts); n++ {
			directories[strings.Join(parts[:n], "/")] = true
		}
	}
	if expected[RunPath] != runDisk.file {
		return result, ErrDigest
	}
	observed := map[string]diskFile{}
	observedDirs := map[string]os.FileInfo{}
	seenAgain := map[string]bool{}
	var total int64
	entriesSeen := 0
	var walk func(*os.Root, string, bool) error
	walk = func(dir *os.Root, prefix string, rehash bool) (walkErr error) {
		opened, err := dir.Open(".")
		if err != nil {
			return err
		}
		defer func() { walkErr = errors.Join(walkErr, opened.Close()) }()
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			entries, readErr := opened.ReadDir(128)
			for _, entry := range entries {
				entriesSeen++
				if entriesSeen > limits.FileCount*9 {
					return ErrLimit
				}
				name := entry.Name()
				path := name
				if prefix != "" {
					path = prefix + "/" + name
				}
				if !validPath(path) {
					return fmt.Errorf("%w: invalid disk path", ErrInventory)
				}
				info, err := dir.Lstat(name)
				if err != nil {
					return err
				}
				if info.IsDir() {
					if info.Mode()&os.ModeType != os.ModeDir {
						return ErrInventory
					}
					if !directories[path] {
						return fmt.Errorf("%w: extra directory %s", ErrInventory, path)
					}
					if rehash {
						if _, exists := observedDirs[path]; exists {
							return ErrChanged
						}
						observedDirs[path] = info
					} else {
						prior, exists := observedDirs[path]
						if !exists || !sameDiskFile(prior, info) {
							return ErrChanged
						}
					}
					child, err := dir.OpenRoot(name)
					if err != nil {
						return err
					}
					childInfo, statErr := child.Stat(".")
					if statErr != nil || !os.SameFile(info, childInfo) {
						_ = child.Close()
						return errors.Join(ErrChanged, statErr)
					}
					childErr := walk(child, path, rehash)
					closeErr := child.Close()
					if err := errors.Join(childErr, closeErr); err != nil {
						return err
					}
					current, err := dir.Lstat(name)
					if err != nil {
						return errors.Join(ErrChanged, err)
					}
					if !sameDiskFile(info, current) {
						return ErrChanged
					}
					continue
				}
				want, exists := expected[path]
				if !exists || !info.Mode().IsRegular() {
					return fmt.Errorf("%w: unexpected/non-regular file %s", ErrInventory, path)
				}
				if rehash {
					if _, exists := observed[path]; exists {
						return ErrChanged
					}
					if len(observed) >= limits.FileCount {
						return ErrLimit
					}
					_, record, err := readDiskFile(ctx, dir, name, min(limits.FileBytes, limits.PayloadBytes-total), false)
					if err != nil {
						return err
					}
					record.file.Path = path
					if record.file != want {
						return fmt.Errorf("%w: %s", ErrDigest, path)
					}
					total += record.file.Size
					observed[path] = record
				} else {
					record, exists := observed[path]
					if !exists || seenAgain[path] || !sameDiskFile(record.info, info) {
						return ErrChanged
					}
					seenAgain[path] = true
					file, err := openVerificationFile(dir, name)
					if err != nil {
						return err
					}
					openedInfo, checkErr := file.Stat()
					if checkErr == nil && !sameDiskFile(record.info, openedInfo) {
						checkErr = ErrChanged
					}
					if checkErr == nil {
						checkErr = checkVerificationLinks(file, openedInfo)
					}
					if err := errors.Join(checkErr, file.Close()); err != nil {
						return err
					}
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	}
	if err := walk(root, "", true); err != nil {
		return result, err
	}
	if len(observed) != len(expected) {
		return result, fmt.Errorf("%w: missing files", ErrInventory)
	}
	entriesSeen = 0
	if err := walk(root, "", false); err != nil {
		return result, err
	}
	if len(seenAgain) != len(observed) {
		return result, ErrChanged
	}
	// Recheck marker bytes, not merely their timestamps, after hashing payload.
	for _, marker := range []diskFile{runDisk, commitDisk} {
		_, current, err := readDiskFile(ctx, root, marker.file.Path, min(limits.MetadataBytes, limits.FileBytes), false)
		if err != nil {
			return result, err
		}
		if current.file != marker.file || !sameDiskFile(marker.info, current.info) {
			return result, ErrChanged
		}
	}
	current, err := os.Lstat(directory)
	if err != nil {
		return result, errors.Join(ErrChanged, err)
	}
	if !sameDiskFile(before, current) {
		return result, ErrChanged
	}
	return Verification{Managed: true, Run: run, Commit: commit, FileCount: len(observed), PayloadBytes: total}, nil
}
