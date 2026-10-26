//go:build !darwin && !linux

package packageio

import "io/fs"

// In particular, Windows FileInfo.Sys does not expose SameFile's complete
// identity. Preserve the old pairwise check until native behavior is validated.
func sourceIdentityKey(info fs.FileInfo) (sourceFileKey, bool) {
	return sourceFileKey{}, false
}
