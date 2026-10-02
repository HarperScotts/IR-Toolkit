package collector

import (
	"context"
	"fmt"
)

type UnsupportedCollector struct {
	name string
}

func (c *UnsupportedCollector) Name() string {
	return c.name
}

func (c *UnsupportedCollector) Collect(
	ctx context.Context,
) (any, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return nil, fmt.Errorf(
		"collector %q is not supported on this operating system",
		c.name,
	)
}

func newUnsupportedCollector(
	name string,
) Collector {

	return &UnsupportedCollector{
		name: name,
	}
}
