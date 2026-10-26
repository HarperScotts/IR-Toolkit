package linux

import (
	"context"

	"ir-toolkit/internal/model"
)

type CapabilityCollector struct{}

func (c *CapabilityCollector) Name() string {
	return "linux_capabilities"
}

func (c *CapabilityCollector) Collect(
	ctx context.Context,
) (any, error) {

	return model.AuditCapabilitySnapshot{
		CollectionMode: "snapshot_only",

		Warnings: []string{
			"Linux capability detection is not implemented yet",
			"Linux coverage percentages are not quantified; zero is not proof of no evidence and 100 percent coverage is not claimed",
		},
	}, nil
}
