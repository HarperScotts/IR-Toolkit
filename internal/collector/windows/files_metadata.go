//go:build windows

package windows

import (
	"os"
	"syscall"
	"time"
)

func getWindowsCreationTime(
	info os.FileInfo,
) time.Time {

	data, ok :=
		info.Sys().(*syscall.Win32FileAttributeData)

	if !ok ||
		data == nil {

		return time.Time{}
	}

	return time.Unix(
		0,
		data.
			CreationTime.
			Nanoseconds(),
	).UTC()
}

func getWindowsAccessTime(
	info os.FileInfo,
) time.Time {

	data, ok :=
		info.Sys().(*syscall.Win32FileAttributeData)

	if !ok ||
		data == nil {

		return time.Time{}
	}

	return time.Unix(
		0,
		data.
			LastAccessTime.
			Nanoseconds(),
	).UTC()
}
