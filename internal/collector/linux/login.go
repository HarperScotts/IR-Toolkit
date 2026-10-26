package linux

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"

	"ir-toolkit/internal/model"
)

type LoginCollector struct{}

func (c *LoginCollector) Name() string {
	return "linux_login"
}

func (c *LoginCollector) Collect(
	ctx context.Context,
) (any, error) {

	result, rawErr := collectLinuxLogin(ctx, "/", 8<<20, 24<<20)
	login1, login1Err := collectPlatformLogin1(ctx)
	result.LinuxLogin1 = &login1
	result.Warnings = append(result.Warnings, login1.Warnings...)
	if login1Err != nil {
		result.Warnings = append(result.Warnings, "Linux login1 incomplete: "+login1Err.Error())
	}
	return result, errors.Join(rawErr, login1Err)
}

var linuxLoginPaths = []struct{ path, kind string }{
	{"/var/log/auth.log", "auth_log"}, {"/var/log/auth.log.1", "auth_log"},
	{"/var/log/secure", "auth_log"}, {"/var/log/secure.1", "auth_log"},
	{"/run/utmp", "current_accounting"}, {"/var/log/wtmp", "historical_accounting"}, {"/var/log/btmp", "failed_accounting"},
}

func collectLinuxLogin(ctx context.Context, rootPath string, fileLimit, totalLimit int64) (model.LoginSnapshot, error) {
	result := model.LoginSnapshot{Warnings: []string{
		"Linux login scope: raw-file part covers fixed auth.log/secure files (current and .1) and utmp/wtmp/btmp only; login1 is a separate live source. Journal, audit, compressed rotations and other file sources are not covered. Raw files are not filtered by the requested collection time window.",
		"Accounting files remain opaque bytes: current sessions and binary history are not decoded. SSH log claims do not establish a complete session, process identity or execution; absent files/records do not prove absence of activity.",
		"Login collection is a live, non-atomic read; file changes/limits/permissions retain errors, not truncated successful content. Reading may update access times.",
	}}
	if ctx == nil {
		return result, fmt.Errorf("login collection context required")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		result.Warnings = append(result.Warnings, "Cannot open login source root: "+err.Error())
		return result, err
	}
	defer root.Close()
	var failures []error
	var consumed int64
	for _, source := range linuxLoginPaths {
		artifact := model.LinuxLoginArtifact{Path: source.path, Kind: source.kind, Status: "observed"}
		fail := func(err error) {
			artifact.Status = "error"
			artifact.Content = nil
			artifact.SHA256 = ""
			artifact.ReadError = err.Error()
			failures = append(failures, fmt.Errorf("%s: %w", source.path, err))
		}
		if err := ctx.Err(); err != nil {
			artifact.Status = "not_scanned"
			artifact.ReadError = err.Error()
			failures = append(failures, err)
			result.LinuxArtifacts = append(result.LinuxArtifacts, artifact)
			continue
		}
		name := strings.TrimPrefix(source.path, "/")
		info, err := root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			artifact.Status = "missing"
		} else if err != nil {
			fail(err)
		} else {
			artifact.Mode, artifact.Size, artifact.ModifiedAt = info.Mode().String(), info.Size(), info.ModTime().UTC()
			artifact.UID, artifact.GID = persistenceOwner(info)
			if info.Mode()&os.ModeSymlink != 0 {
				artifact.LinkTarget, err = root.Readlink(name)
				if err == nil {
					after, statErr := root.Lstat(name)
					err = statErr
					if err == nil && (!os.SameFile(info, after) || info.ModTime() != after.ModTime()) {
						err = fmt.Errorf("login source link changed during read")
					}
				}
				if err == nil {
					err = fmt.Errorf("login source is a symbolic link; target not followed")
				}
				fail(err)
			} else if !info.Mode().IsRegular() {
				fail(fmt.Errorf("login source is not a regular file; not opened"))
			} else {
				data, n, readErr := readStableLinuxFile(ctx, root, name, info, min(fileLimit, totalLimit-consumed))
				consumed += n
				if readErr != nil {
					fail(readErr)
				} else {
					sum := sha256.Sum256(data)
					artifact.Content, artifact.SHA256 = data, fmt.Sprintf("%x", sum)
				}
			}
		}
		result.LinuxArtifacts = append(result.LinuxArtifacts, artifact)
	}
	for _, artifact := range result.LinuxArtifacts {
		if artifact.Status == "error" || artifact.Status == "not_scanned" {
			result.Warnings = append(result.Warnings, "Incomplete Linux login source: "+artifact.Path+": "+artifact.ReadError)
		}
	}
	return result, errors.Join(failures...)
}
