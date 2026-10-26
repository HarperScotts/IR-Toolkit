package linux

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

type socketOwner struct {
	PID        uint32
	InstanceID string
}

// The key is scoped to one running procfs collection/case, not a global ID or
// a historical identity. Start ticks come directly from stat field 22.
func procInstance(data []byte, pid uint32) (string, error) {
	text := string(data)
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 0 || close <= open {
		return "", fmt.Errorf("invalid proc stat identity")
	}
	actual, err := strconv.ParseUint(strings.TrimSpace(text[:open]), 10, 32)
	if err != nil || uint32(actual) != pid || pid == 0 {
		return "", fmt.Errorf("proc PID changed/invalid")
	}
	fields := strings.Fields(text[close+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("missing proc start ticks")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("linux-proc:%d:%d", pid, ticks), nil
}

func processSocketInodes(ctx context.Context, root *os.Root, pid uint32, namespace string, wanted map[uint64]bool, fdCount *int) ([]uint64, string, error) {
	process, err := root.OpenRoot(strconv.FormatUint(uint64(pid), 10))
	if err != nil {
		return nil, "", err
	}
	defer process.Close()
	ns, err := process.Readlink("ns/net")
	if err != nil {
		return nil, "", err
	}
	if ns != namespace {
		return nil, "", nil
	}
	before, err := readProcBounded(process, "stat", 64<<10)
	if err != nil {
		return nil, "", err
	}
	instance, err := procInstance(before, pid)
	if err != nil {
		return nil, "", err
	}
	dir, err := process.Open("fd")
	if err != nil {
		return nil, "", err
	}
	defer dir.Close()
	var found []uint64
	for {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			*fdCount += 1
			if *fdCount > maxNetworkFDs {
				return nil, "", fmt.Errorf("socket fd enumeration limit")
			}
			if _, err := strconv.ParseUint(entry.Name(), 10, 64); err != nil {
				continue
			}
			target, err := process.Readlink("fd/" + entry.Name())
			if err != nil {
				continue
			} // Closed/replaced fds do not produce an owner.
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode, err := strconv.ParseUint(target[8:len(target)-1], 10, 64)
			if err == nil && inode != 0 && wanted[inode] {
				found = append(found, inode)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, "", readErr
		}
	}
	after, err := readProcBounded(process, "stat", 64<<10)
	if err != nil {
		return nil, "", err
	}
	endInstance, err := procInstance(after, pid)
	if err != nil {
		return nil, "", err
	}
	endNS, err := process.Readlink("ns/net")
	if err != nil {
		return nil, "", err
	}
	if instance != endInstance || ns != endNS {
		return nil, "", fmt.Errorf("process identity/namespace changed")
	}
	return found, instance, nil
}

func socketOwners(ctx context.Context, root *os.Root, namespace string, wanted map[uint64]bool) (map[uint64]socketOwner, error) {
	owners := map[uint64]socketOwner{}
	if len(wanted) == 0 {
		return owners, nil
	}
	dir, err := root.Open(".")
	if err != nil {
		return owners, err
	}
	defer dir.Close()
	fdCount, processCount, unreadable := 0, 0, 0
	for {
		if err := ctx.Err(); err != nil {
			return owners, err
		}
		entries, readErr := dir.ReadDir(256)
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil || pid == 0 {
				continue
			}
			processCount++
			if processCount > maxNetworkProcesses {
				return owners, fmt.Errorf("process enumeration limit")
			}
			inodes, instance, err := processSocketInodes(ctx, root, uint32(pid), namespace, wanted, &fdCount)
			if fdCount > maxNetworkFDs {
				return owners, err
			}
			if err != nil {
				unreadable++
				continue
			}
			owner := socketOwner{uint32(pid), instance}
			for _, inode := range inodes {
				previous, exists := owners[inode]
				if !exists {
					owners[inode] = owner
				} else if previous != owner {
					owners[inode] = socketOwner{}
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return owners, readErr
		}
	}
	if unreadable > 0 {
		return owners, fmt.Errorf("%d process fd/identity observations unavailable (exit, permissions or change)", unreadable)
	}
	return owners, nil
}
