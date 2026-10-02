package linux

import (
	"context"

	"ir-toolkit/internal/model"
)

type SecurityProviderCollector struct{}

func (c *SecurityProviderCollector) Name() string {
	return "linux_security_providers"
}

func (c *SecurityProviderCollector) Collect(
	ctx context.Context,
) (any, error) {

	return model.SecurityProviderSnapshot{
		Warnings: []string{
			"Linux security provider discovery is not implemented yet",
		},
	}, nil
}
