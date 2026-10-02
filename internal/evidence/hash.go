package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

func SHA256File(
	path string,
) (string, int64, error) {

	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", 0, err
	}

	hash := sha256.New()

	if _, err := io.Copy(
		hash,
		file,
	); err != nil {
		return "", 0, err
	}

	return hex.EncodeToString(
		hash.Sum(nil),
	), info.Size(), nil
}