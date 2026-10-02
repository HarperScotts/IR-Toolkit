//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type LoginCollector struct{}

func (c *LoginCollector) Name() string {
	return "windows_login"
}

func (c *LoginCollector) Collect(
	ctx context.Context,
) (any, error) {

	result := model.LoginSnapshot{
		Sessions: make(
			[]model.LoginSession,
			0,
		),

		Events: make(
			[]model.LoginEvent,
			0,
		),

		Warnings: make(
			[]string,
			0,
		),
	}

	// ----------------------------------------
	// Current sessions
	// ----------------------------------------

	sessions, warnings :=
		collectWindowsSessions(
			ctx,
		)

	result.Sessions =
		sessions

	result.Warnings =
		append(
			result.Warnings,
			warnings...,
		)

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// ----------------------------------------
	// Security Event Log
	// ----------------------------------------

	events, warnings :=
		collectWindowsLoginEvents(
			ctx,
		)

	result.Events = events

	result.Statistics.SessionCount =
		uint32(
			len(result.Sessions),
		)

	result.Statistics.EventCount =
		uint32(
			len(result.Events),
		)

	for _, event := range result.Events {

		switch event.EventID {

		case 4624:

			result.Statistics.
				SuccessfulLogons++

		case 4625:

			result.Statistics.
				FailedLogons++

		case 4648:

			result.Statistics.
				ExplicitCredentialEvents++

		case 4672:

			result.Statistics.
				PrivilegedLogons++
		}
	}

	result.Warnings =
		append(
			result.Warnings,
			warnings...,
		)

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"login collection completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
