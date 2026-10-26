//go:build darwin || linux

package packageio

import (
	"io/fs"
	"syscall"
)

// Go's os.SameFile compares Stat_t.Dev and Stat_t.Ino on these platforms.
// Do not use size/mtime/link count: aliases can be observed across a mutation.
func sourceIdentityKey(info fs.FileInfo) (sourceFileKey, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return sourceFileKey{}, false
	}
	return sourceFileKey{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, true
}
