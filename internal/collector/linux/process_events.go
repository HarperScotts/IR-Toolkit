package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

type ProcessEventCollector struct{}

func (c *ProcessEventCollector) Name() string {
	return "linux_process_events"
}

func (c *ProcessEventCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.ProcessEventSnapshot{
			Warnings: []string{
				"Linux process event collector is not implemented yet",
			},
		}

	return result,
		fmt.Errorf(
			"Linux process event collector is not implemented yet",
		)
}
