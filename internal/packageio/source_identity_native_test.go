//go:build darwin || linux

package packageio

import (
	"io/fs"
	"syscall"
	"testing"
)

type sourceInfoWithStat struct {
	fs.FileInfo
	stat *syscall.Stat_t
}

func (info sourceInfoWithStat) Sys() any { return info.stat }

func TestSourceIdentityNativeKey(t *testing.T) {
	if _, ok := sourceIdentityKey(sourceInfoWithStat{}); ok {
		t.Fatal("typed nil stat is not an identity")
	}
	first, ok := sourceIdentityKey(sourceInfoWithStat{stat: &syscall.Stat_t{Dev: 1, Ino: 7}})
	if !ok {
		t.Fatal("native key missing")
	}
	otherDevice, _ := sourceIdentityKey(sourceInfoWithStat{stat: &syscall.Stat_t{Dev: 2, Ino: 7}})
	otherInode, _ := sourceIdentityKey(sourceInfoWithStat{stat: &syscall.Stat_t{Dev: 1, Ino: 8}})
	if first == otherDevice || first == otherInode {
		t.Fatal("device/inode distinction lost")
	}
}
