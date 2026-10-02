package linux

import (
	"context"
	"fmt"

	"ir-toolkit/internal/model"
)

type LoginCollector struct{}

func (c *LoginCollector) Name() string {
	return "linux_login"
}

func (c *LoginCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.LoginSnapshot{
			Warnings: []string{
				"Linux login collector is not implemented yet",
			},
		}

	return result,
		fmt.Errorf(
			"Linux login collector is not implemented yet",
		)
}
