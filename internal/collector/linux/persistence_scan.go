package linux

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
)

// Fixed read-only inventory: no home traversal, commands or manager interaction.
// Source aliases remain distinct observed paths, not deduplicated effective units.
var linuxPersistenceSources = []struct {
	path, kind string
	directory  bool
}{
	{"/etc/systemd/system.control", "systemd", true},
	{"/run/systemd/system.control", "systemd", true},
	{"/run/systemd/transient", "systemd", true},
	{"/etc/systemd/system.attached", "systemd", true},
	{"/run/systemd/system.attached", "systemd", true},
	{"/etc/systemd/system", "systemd", true},
	{"/run/systemd/system", "systemd", true},
	{"/usr/local/lib/systemd/system", "systemd", true},
	{"/usr/lib/systemd/system", "systemd", true},
	{"/lib/systemd/system", "systemd", true},
	{"/etc/systemd/user", "systemd", true},
	{"/run/systemd/user", "systemd", true},
	{"/usr/local/lib/systemd/user", "systemd", true},
	{"/usr/lib/systemd/user", "systemd", true},
	{"/lib/systemd/user", "systemd", true},
	{"/run/systemd/generator", "systemd", true},
	{"/run/systemd/generator.early", "systemd", true},
	{"/run/systemd/generator.late", "systemd", true},
	{"/etc/crontab", "cron", false},
	{"/etc/anacrontab", "cron", false},
	{"/etc/cron.d", "cron", true},
	{"/etc/cron.hourly", "cron", true},
	{"/etc/cron.daily", "cron", true},
	{"/etc/cron.weekly", "cron", true},
	{"/etc/cron.monthly", "cron", true},
	{"/var/spool/cron", "cron", true},
	{"/var/spool/cron/crontabs", "cron", true},
}

type persistenceLimits struct {
	artifacts, entries    int
	fileBytes, totalBytes int64
}
type persistenceScan struct {
	ctx      context.Context
	result   model.PersistenceSnapshot
	limits   persistenceLimits
	entries  int
	bytes    int64
	failures []error
}

func collectPersistence(ctx context.Context, rootPath string, limits persistenceLimits) (model.PersistenceSnapshot, error) {
	s := persistenceScan{ctx: ctx, limits: limits, result: model.PersistenceSnapshot{Warnings: []string{
		"Linux persistence scope: fixed system-level systemd/cron paths only; user homes, custom load paths and other mechanisms are not covered.",
		"Persistence candidates are raw observations, not proof of activation or execution; full effective unit/drop-in/cron parsing across sources is not established by the snapshot. Conditional projections do not prove manager state; process correlation is not implemented.",
		"Live files are not an atomic snapshot; metadata and hashes describe observed bytes, not execution history. Reading may update access times.",
	}}}
	if ctx == nil {
		return s.result, fmt.Errorf("persistence collection context required")
	}
	if err := ctx.Err(); err != nil {
		s.result.Warnings = append(s.result.Warnings, err.Error())
		return s.result, err
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		s.result.Warnings = append(s.result.Warnings, "Cannot open persistence root: "+err.Error())
		return s.result, err
	}
	defer root.Close()
	for _, source := range linuxPersistenceSources {
		status := model.LinuxPersistenceSource{Path: source.path, Kind: source.kind, Status: "observed"}
		if err := s.check(); err != nil {
			status.Status, status.Error = "not_scanned", err.Error()
			s.failures = append(s.failures, err)
		} else if source.directory {
			dir, err := root.OpenRoot(strings.TrimPrefix(source.path, "/"))
			if errors.Is(err, os.ErrNotExist) {
				status.Status = "missing"
			} else if err != nil {
				status.Status, status.Error = "error", err.Error()
				s.failures = append(s.failures, fmt.Errorf("%s: %w", source.path, err))
			} else {
				before := len(s.failures)
				s.walk(dir, source.path, source.kind, 0)
				dir.Close()
				if len(s.failures) != before {
					status.Status = "partial"
					status.Error = errors.Join(s.failures[before:]...).Error()
				}
			}
		} else {
			before := len(s.failures)
			if _, err := root.Lstat(strings.TrimPrefix(source.path, "/")); errors.Is(err, os.ErrNotExist) {
				status.Status = "missing"
			} else {
				s.capture(root, strings.TrimPrefix(source.path, "/"), source.path, source.kind)
				if len(s.failures) != before {
					status.Status = "partial"
					status.Error = errors.Join(s.failures[before:]...).Error()
				}
			}
		}
		s.result.LinuxSources = append(s.result.LinuxSources, status)
	}
	for _, source := range s.result.LinuxSources {
		if source.Status != "observed" && source.Status != "missing" {
			s.result.Warnings = append(s.result.Warnings, "Incomplete persistence source: "+source.Path+" ("+source.Status+") "+source.Error)
		}
	}
	if len(s.failures) > 0 {
		s.result.Warnings = append(s.result.Warnings, "Persistence collection incomplete; inspect artifact read_error and source status. Unread files have no content/hash.")
	}
	sort.Slice(s.result.LinuxArtifacts, func(i, j int) bool { return s.result.LinuxArtifacts[i].Path < s.result.LinuxArtifacts[j].Path })
	return s.result, errors.Join(s.failures...)
}

func (s *persistenceScan) check() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if len(s.result.LinuxArtifacts) >= s.limits.artifacts {
		return fmt.Errorf("persistence artifact limit")
	}
	if s.entries >= s.limits.entries {
		return fmt.Errorf("persistence directory entry limit")
	}
	return nil
}

func systemdCandidate(name string) bool {
	switch path.Ext(name) {
	case ".service", ".timer", ".socket", ".path", ".target", ".mount", ".automount", ".swap", ".slice", ".scope":
		return true
	}
	return false
}

func (s *persistenceScan) walk(dir *os.Root, source, kind string, depth int) {
	file, err := dir.Open(".")
	if err != nil {
		s.failures = append(s.failures, fmt.Errorf("%s: %w", source, err))
		return
	}
	defer file.Close()
	for {
		if err := s.check(); err != nil {
			s.failures = append(s.failures, fmt.Errorf("%s: %w", source, err))
			return
		}
		entries, readErr := file.ReadDir(128)
		for _, entry := range entries {
			if err := s.check(); err != nil {
				s.failures = append(s.failures, err)
				return
			}
			s.entries++
			name := entry.Name()
			info, err := dir.Lstat(name)
			if err != nil {
				s.capture(dir, name, path.Join(source, name), kind)
				continue
			}
			if info.IsDir() {
				// A directory occupying a unit/drop-in filename is not evidence
				// that the higher-priority filename is absent. Retain the type
				// error so analysis cannot silently fall back to vendor content.
				if kind == "systemd" && (systemdCandidate(name) || depth == 1 && strings.HasSuffix(source, ".d") && strings.HasSuffix(name, ".conf")) {
					s.capture(dir, name, path.Join(source, name), kind)
					continue
				}
				if kind != "systemd" || depth != 0 || !(strings.HasSuffix(name, ".d") || strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires") || strings.HasSuffix(name, ".upholds")) {
					continue
				}
				child, err := dir.OpenRoot(name)
				if err == nil {
					var actual os.FileInfo
					actual, err = child.Stat(".")
					if err == nil && !os.SameFile(info, actual) {
						err = fmt.Errorf("directory identity changed")
					}
					if err == nil {
						s.walk(child, path.Join(source, name), kind, depth+1)
					}
					child.Close()
				}
				if err != nil {
					s.failures = append(s.failures, fmt.Errorf("%s: %w", path.Join(source, name), err))
				}
				continue
			}
			linkDirectory := info.Mode()&os.ModeSymlink != 0 && (strings.HasSuffix(name, ".d") || strings.HasSuffix(name, ".wants") || strings.HasSuffix(name, ".requires") || strings.HasSuffix(name, ".upholds"))
			if kind == "systemd" && !systemdCandidate(name) && !linkDirectory && !(depth == 1 && strings.HasSuffix(source, ".d") && strings.HasSuffix(name, ".conf")) {
				continue
			}
			s.capture(dir, name, path.Join(source, name), kind)
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			s.failures = append(s.failures, fmt.Errorf("%s: %w", source, readErr))
			return
		}
	}
}

func (s *persistenceScan) capture(root *os.Root, relative, source, kind string) {
	a := model.LinuxPersistenceArtifact{Kind: kind, Path: source}
	fail := func(err error) {
		a.Content, a.SHA256 = nil, ""
		a.ReadError = err.Error()
		s.failures = append(s.failures, fmt.Errorf("%s: %w", source, err))
	}
	info, err := root.Lstat(relative)
	if err != nil {
		fail(err)
		s.result.LinuxArtifacts = append(s.result.LinuxArtifacts, a)
		return
	}
	a.Mode, a.Size, a.ModifiedAt = info.Mode().String(), info.Size(), info.ModTime().UTC()
	a.UID, a.GID = persistenceOwner(info)
	if info.Mode()&os.ModeSymlink != 0 {
		a.LinkTarget, err = root.Readlink(relative)
		if err == nil {
			var after os.FileInfo
			after, err = root.Lstat(relative)
			if err == nil && (!os.SameFile(info, after) || info.ModTime() != after.ModTime()) {
				err = fmt.Errorf("symlink changed during read")
			}
		}
		if err != nil {
			a.LinkTarget = ""
			fail(err)
		}
	} else if !info.Mode().IsRegular() {
		fail(fmt.Errorf("not a regular file; content not opened"))
	} else if info.Size() > s.limits.fileBytes || info.Size() > s.limits.totalBytes-s.bytes {
		fail(fmt.Errorf("persistence content byte limit"))
	} else if err := s.readContent(root, relative, info, &a); err != nil {
		fail(err)
	}
	s.result.LinuxArtifacts = append(s.result.LinuxArtifacts, a)
}

func (s *persistenceScan) readContent(root *os.Root, name string, before os.FileInfo, a *model.LinuxPersistenceArtifact) error {
	maximum := min(s.limits.fileBytes, s.limits.totalBytes-s.bytes)
	data, consumed, err := readStableLinuxFile(s.ctx, root, name, before, maximum)
	s.bytes += consumed
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	a.Content, a.SHA256 = data, fmt.Sprintf("%x", sum)
	return nil
}
