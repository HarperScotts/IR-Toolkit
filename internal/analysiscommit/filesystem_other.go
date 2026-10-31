//go:build !windows && !darwin && !linux && !freebsd && !netbsd && !openbsd && !dragonfly

package analysiscommit

import (
	"fmt"
	"os"
)

func openVerificationFile(_ *os.Root, _ string) (*os.File, error) {
	return nil, fmt.Errorf("%w: filesystem verification unsupported on this platform", ErrInvalid)
}
func checkVerificationLinks(_ *os.File, _ os.FileInfo) error { return ErrInvalid }
