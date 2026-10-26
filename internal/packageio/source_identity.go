package packageio

import (
	"io/fs"
	"os"
)

type sourceFileKey struct {
	device uint64
	inode  uint64
}

// An operation-local index; no identity survives the source walk. Only native
// keys matching SameFile semantics accelerate lookup. Unknown identities and
// key collisions retain the conservative pairwise fallback.
type sourceIdentityIndex struct {
	keyed    map[sourceFileKey]fs.FileInfo
	fallback []fs.FileInfo
}

// add reports an alias using SameFile, never merely a key/hash match.
func (index *sourceIdentityIndex) add(info fs.FileInfo) bool {
	key, ok := sourceIdentityKey(info)
	for _, previous := range index.fallback {
		if os.SameFile(previous, info) {
			return true
		}
	}
	if !ok {
		for _, previous := range index.keyed {
			if os.SameFile(previous, info) {
				return true
			}
		}
		index.fallback = append(index.fallback, info)
		return false
	}
	if previous, exists := index.keyed[key]; exists {
		if os.SameFile(previous, info) {
			return true
		}
		// A non-native FileInfo may expose a coincident key without satisfying
		// SameFile. Keep it visible to every subsequent identity check.
		index.fallback = append(index.fallback, info)
		return false
	}
	if index.keyed == nil {
		index.keyed = make(map[sourceFileKey]fs.FileInfo)
	}
	index.keyed[key] = info
	return false
}
