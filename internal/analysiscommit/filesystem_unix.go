//go:build darwin || linux || freebsd || netbsd || openbsd || dragonfly

package analysiscommit

import (
	"fmt"
	"os"
	"syscall"
)

func openVerificationFile(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
func checkVerificationLinks(_ *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return fmt.Errorf("%w: hard links or unknown link count", ErrInventory)
	}
	return nil
}
