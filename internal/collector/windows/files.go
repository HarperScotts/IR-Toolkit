//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type FileCollector struct{}

func (c *FileCollector) Name() string {
	return "windows_files"
}

func (c *FileCollector) Collect(
	ctx context.Context,
) (any, error) {

	roots :=
		buildWindowsTriageRoots()

	result :=
		model.FileTriageSnapshot{
			Files: make(
				[]model.FileTriageItem,
				0,
			),

			ScannedRoots: roots,

			Warnings: make(
				[]string,
				0,
			),
		}

	for _, root := range roots {

		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		files, warnings :=
			collectFilesFromRoot(
				ctx,
				root,
			)

		result.Files =
			append(
				result.Files,
				files...,
			)

		result.Warnings =
			append(
				result.Warnings,
				warnings...,
			)
	}

	result.Statistics.RootCount =
		uint32(
			len(result.ScannedRoots),
		)

	result.Statistics.FileCount =
		uint32(
			len(result.Files),
		)

	for _, file := range result.Files {

		if file.SHA256 != "" {
			result.Statistics.
				HashedCount++
		}

		if file.Executable {
			result.Statistics.
				ExecutableCount++
		}

		if len(file.ADS) > 0 {
			result.Statistics.
				ADSCount++
		}
	}

	result.Warnings =
		uniqueWarningStrings(
			result.Warnings,
		)

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"file triage completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
