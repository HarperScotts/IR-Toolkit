//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func hashTriageFile(
	path string,
) string {

	file, err :=
		os.Open(path)

	if err != nil {
		return ""
	}

	defer file.Close()

	hash :=
		sha256.New()

	if _, err :=
		io.Copy(
			hash,
			file,
		); err != nil {

		return ""
	}

	return hex.EncodeToString(
		hash.Sum(nil),
	)
}
