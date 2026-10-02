//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type PersistenceCollector struct{}

func (c *PersistenceCollector) Name() string {
	return "windows_persistence"
}

func (c *PersistenceCollector) Collect(
	ctx context.Context,
) (any, error) {

	result := model.PersistenceSnapshot{
		Services:       make([]model.ServiceInfo, 0),
		RunKeys:        make([]model.RegistryRunEntry, 0),
		ScheduledTasks: make([]model.ScheduledTask, 0),
		Warnings:       make([]string, 0),
	}

	// Services
	services, warnings :=
		collectWindowsServices(ctx)

	result.Services = services

	result.Warnings = append(
		result.Warnings,
		warnings...,
	)

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Run Keys
	runKeys, warnings :=
		collectRegistryRunKeys(ctx)

	result.RunKeys = runKeys

	result.Warnings = append(
		result.Warnings,
		warnings...,
	)

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Scheduled Tasks
	tasks, warnings :=
		collectScheduledTasks(ctx)

	result.ScheduledTasks = tasks

	result.Warnings = append(
		result.Warnings,
		warnings...,
	)

	// 有分类级采集问题时仍然保留已采集数据。
	if len(result.Warnings) > 0 {

		return result, fmt.Errorf(
			"persistence collection completed with warnings: %s",
			strings.Join(
				result.Warnings,
				"; ",
			),
		)
	}

	return result, nil
}
