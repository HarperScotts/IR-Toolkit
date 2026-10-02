package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

type FileCollector struct{}

func (c *FileCollector) Name() string {
	return "linux_files"
}

func (c *FileCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.FileTriageSnapshot{
			Warnings: []string{
				"Linux file triage collector is not implemented yet",
			},
		}

	return result,
		fmt.Errorf(
			"Linux file triage collector is not implemented yet",
		)
}
