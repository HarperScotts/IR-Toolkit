//go:build windows

package analysiscommit

import (
	"fmt"
	"os"
	"syscall"
)

func openVerificationFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
func checkVerificationLinks(file *os.File, _ os.FileInfo) error {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.NumberOfLinks != 1 || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: hard link or reparse point", ErrInventory)
	}
	return nil
}
