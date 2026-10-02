//go:build windows

package windows

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/model"
)

const (
	maxTriageFileSize = 128 * 1024 * 1024

	maxFilesPerRoot = 10000
)

func collectFilesFromRoot(
	ctx context.Context,
	root string,
) ([]model.FileTriageItem, []string) {

	result :=
		make(
			[]model.FileTriageItem,
			0,
		)

	warnings :=
		make(
			[]string,
			0,
		)

	info, err :=
		os.Stat(root)

	if err != nil {

		if os.IsNotExist(err) {
			return result, warnings
		}

		return result,
			[]string{
				fmt.Sprintf(
					"stat %s: %v",
					root,
					err,
				),
			}
	}

	if !info.IsDir() {
		return result, warnings
	}

	window :=
		collection.TimeWindowFromContext(
			ctx,
		)

	if window.Empty() {

		until :=
			time.Now().UTC()

		since :=
			until.Add(
				-24 * time.Hour,
			)

		window.Since =
			&since

		window.Until =
			&until
	}

	count := 0

	walkErr :=
		filepath.WalkDir(
			root,

			func(
				path string,
				entry fs.DirEntry,
				err error,
			) error {

				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
				}

				if err != nil {

					warnings =
						append(
							warnings,
							fmt.Sprintf(
								"walk %s: %v",
								path,
								err,
							),
						)

					return nil
				}

				if entry.IsDir() {
					return nil
				}

				if count >=
					maxFilesPerRoot {

					return fs.SkipAll
				}

				fileInfo, err :=
					entry.Info()

				if err != nil {
					return nil
				}

				// 时间窗口存在时：
				// Created / Modified 任一个落在窗口内即可。
				if !window.Empty() {

					created :=
						getWindowsCreationTime(
							fileInfo,
						)

					modified :=
						fileInfo.ModTime()

					if !window.Contains(
						created,
					) &&
						!window.Contains(
							modified,
						) {

						return nil
					}
				}

				item :=
					buildFileTriageItem(
						path,
						fileInfo,
					)

				result =
					append(
						result,
						item,
					)

				count++

				return nil
			},
		)

	if walkErr != nil {

		warnings =
			append(
				warnings,
				fmt.Sprintf(
					"walk root %s: %v",
					root,
					walkErr,
				),
			)
	}

	if count >= maxFilesPerRoot {

		warnings =
			append(
				warnings,
				fmt.Sprintf(
					"file limit reached for %s (%d)",
					root,
					maxFilesPerRoot,
				),
			)
	}

	return result, warnings
}

func buildFileTriageItem(
	path string,
	info os.FileInfo,
) model.FileTriageItem {

	extension :=
		strings.ToLower(
			filepath.Ext(path),
		)

	item :=
		model.FileTriageItem{
			Path: path,

			Name: info.Name(),

			Extension: extension,

			Size: info.Size(),

			CreatedAt: getWindowsCreationTime(
				info,
			),

			ModifiedAt: info.ModTime().
				UTC(),

			AccessedAt: getWindowsAccessTime(
				info,
			),

			Executable: isInterestingExecutable(
				extension,
			),

			Source: "windows_file_triage",
		}

	item.Owner =
		getFileOwner(
			path,
		)

	item.ADS =
		getAlternateDataStreams(
			path,
		)

	item.ZoneIdentifier =
		readZoneIdentifier(
			path,
		)

	if shouldHashFile(
		item,
	) {

		item.SHA256 =
			hashTriageFile(
				path,
			)
	}

	return item
}

func isInterestingExecutable(
	extension string,
) bool {

	switch strings.ToLower(
		extension,
	) {

	case ".exe",
		".dll",
		".sys",
		".scr",
		".com",

		".ps1",
		".psm1",

		".bat",
		".cmd",

		".vbs",
		".vbe",

		".js",
		".jse",

		".hta",

		".jar":

		return true
	}

	return false
}

func shouldHashFile(
	item model.FileTriageItem,
) bool {

	if !item.Executable {
		return false
	}

	if item.Size < 0 ||
		item.Size >
			maxTriageFileSize {

		return false
	}

	return true
}
