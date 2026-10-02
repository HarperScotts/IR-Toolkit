package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

type PersistenceCollector struct{}

func (c *PersistenceCollector) Name() string {
	return "linux_persistence"
}

func (c *PersistenceCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.PersistenceSnapshot{
			Warnings: []string{
				"Linux persistence collector is not implemented yet",
			},
		}

	return result,
		fmt.Errorf(
			"Linux persistence collector is not implemented yet",
		)
}
