package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// LinuxPersistenceInputDigest binds a projection to all raw Linux inputs it uses,
// including absent/partial source evidence and bytes (not just claimed hashes).
// No filesystem access or investigative interpretation is performed here.
// Input order is deliberately significant: even a reordered case revalidates.
func LinuxPersistenceInputDigest(snapshot PersistenceSnapshot) string {
	hash := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.LittleEndian.PutUint64(size[:], uint64(len(value)))
		hash.Write(size[:])
		hash.Write([]byte(value))
	}
	write("linux-persistence-input-v1")
	write("sources")
	write(strconv.Itoa(len(snapshot.LinuxSources)))
	for _, source := range snapshot.LinuxSources {
		write(source.Path)
		write(source.Kind)
		write(source.Status)
		write(source.Error)
	}
	write("artifacts")
	write(strconv.Itoa(len(snapshot.LinuxArtifacts)))
	for _, artifact := range snapshot.LinuxArtifacts {
		write(artifact.Path)
		write(artifact.Kind)
		write(artifact.Mode)
		write(artifact.SHA256)
		write(artifact.LinkTarget)
		write(artifact.ReadError)
		sum := sha256.Sum256(artifact.Content)
		write(hex.EncodeToString(sum[:]))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
