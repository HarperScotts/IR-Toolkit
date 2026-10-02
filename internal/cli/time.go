package cli

import (
	"fmt"
	"strings"
	"time"

	"ir-toolkit/internal/collection"
)

func parseCollectionTimeWindow(
	sinceValue string,
	untilValue string,
	lastValue string,
) (
	collection.TimeWindow,
	error,
) {

	var result collection.TimeWindow

	lastValue =
		strings.TrimSpace(
			lastValue,
		)

	if lastValue != "" {

		if sinceValue != "" ||
			untilValue != "" {

			return result,
				fmt.Errorf(
					"--last cannot be combined with --since or --until",
				)
		}

		duration, err :=
			time.ParseDuration(
				lastValue,
			)

		if err != nil {

			return result,
				fmt.Errorf(
					"invalid --last duration %q: %w",
					lastValue,
					err,
				)
		}

		if duration <= 0 {

			return result,
				fmt.Errorf(
					"--last must be greater than zero",
				)
		}

		now :=
			time.Now().UTC()

		since :=
			now.Add(
				-duration,
			)

		result.Since =
			&since

		result.Until =
			&now

		return result, nil
	}

	sinceValue =
		strings.TrimSpace(
			sinceValue,
		)

	untilValue =
		strings.TrimSpace(
			untilValue,
		)

	if sinceValue != "" {

		value, err :=
			parseCLIAbsoluteTime(
				sinceValue,
			)

		if err != nil {

			return result,
				fmt.Errorf(
					"invalid --since: %w",
					err,
				)
		}

		result.Since =
			&value
	}

	if untilValue != "" {

		value, err :=
			parseCLIAbsoluteTime(
				untilValue,
			)

		if err != nil {

			return result,
				fmt.Errorf(
					"invalid --until: %w",
					err,
				)
		}

		result.Until =
			&value
	}

	if result.Since != nil &&
		result.Until != nil &&
		result.Since.After(
			*result.Until,
		) {

		return result,
			fmt.Errorf(
				"--since must not be later than --until",
			)
	}

	now :=
		time.Now().UTC()

	if result.Since != nil &&
		result.Since.After(
			now,
		) {

		return result,
			fmt.Errorf(
				"--since cannot be in the future",
			)
	}

	return result, nil
}

func parseCLIAbsoluteTime(
	value string,
) (time.Time, error) {

	parsed, err :=
		time.Parse(
			time.RFC3339,
			value,
		)

	if err == nil {
		return parsed.UTC(), nil
	}

	parsed, err =
		time.Parse(
			time.RFC3339Nano,
			value,
		)

	if err == nil {
		return parsed.UTC(), nil
	}

	return time.Time{},
		fmt.Errorf(
			"%q is not RFC3339; example: 2026-09-01T22:30:00+08:00",
			value,
		)
}
