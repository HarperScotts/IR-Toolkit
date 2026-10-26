package local

import (
	"crypto/sha256"
	"fmt"
	"ir-toolkit/internal/model"
)

func setLinuxLoginFixtureHash(artifact *model.LinuxLoginArtifact) {
	sum := sha256.Sum256(artifact.Content)
	artifact.SHA256 = fmt.Sprintf("%x", sum)
}
