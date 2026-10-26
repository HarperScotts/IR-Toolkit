package linux

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

// Pin without opening a device/FIFO for I/O, validate its type, then reopen that
// descriptor through procfs. A pathname replacement cannot redirect the read.
func openPersistenceFile(root *os.Root, name string) (*os.File, error) {
	probe, err := root.OpenFile(name, unix.O_PATH|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer probe.Close()
	info, err := probe.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file; no I/O open")
	}
	return os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", probe.Fd()), os.O_RDONLY|unix.O_NONBLOCK, 0)
}

func persistenceOwner(info os.FileInfo) (*uint32, *uint32) {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid, gid := stat.Uid, stat.Gid
		return &uid, &gid
	}
	return nil, nil
}
