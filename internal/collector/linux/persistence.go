package linux

import (
	"context"
)

type PersistenceCollector struct{}

func (c *PersistenceCollector) Name() string {
	return "linux_persistence"
}

func (c *PersistenceCollector) Collect(
	ctx context.Context,
) (any, error) {

	return collectPersistence(ctx, "/", persistenceLimits{4096, 16384, 1 << 20, 32 << 20})
}
