package linux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// Shared read-only file pinning/change detection. No content is returned for
// incomplete reads; consumed bytes still count against the caller's budget.
func readStableLinuxFile(ctx context.Context, root *os.Root, name string, before os.FileInfo, maximum int64) (data []byte, consumed int64, readErr error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if maximum < 0 || before.Size() > maximum {
		return nil, 0, fmt.Errorf("file content byte limit")
	}
	file, err := openPersistenceFile(root, name)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		readErr = errors.Join(readErr, file.Close())
		if readErr != nil {
			data = nil
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, 0, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, 0, fmt.Errorf("file identity/type changed")
	}
	data, err = io.ReadAll(io.LimitReader(file, maximum+1))
	consumed = int64(len(data))
	if err != nil {
		return nil, consumed, err
	}
	if consumed > maximum {
		return nil, consumed, fmt.Errorf("file content byte limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, consumed, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, consumed, err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return nil, consumed, err
	}
	if !os.SameFile(opened, current) || opened.Size() != before.Size() || opened.ModTime() != before.ModTime() || after.Size() != opened.Size() || after.ModTime() != opened.ModTime() || current.Mode() != before.Mode() || current.ModTime() != after.ModTime() || current.Size() != after.Size() || consumed != after.Size() {
		return nil, consumed, fmt.Errorf("file changed during read")
	}
	return data, consumed, nil
}
