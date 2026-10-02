//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"

	"ir-toolkit/internal/model"
)

type taskXML struct {
	RegistrationInfo struct {
		URI         string `xml:"URI"`
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`

	Principals struct {
		Principal []taskPrincipal `xml:"Principal"`
	} `xml:"Principals"`

	Settings struct {
		Enabled string `xml:"Enabled"`
		Hidden  string `xml:"Hidden"`
	} `xml:"Settings"`

	Actions struct {
		Exec []taskExec `xml:"Exec"`
	} `xml:"Actions"`
}

type taskPrincipal struct {
	UserID string `xml:"UserId"`

	LogonType string `xml:"LogonType"`

	RunLevel string `xml:"RunLevel"`
}

type taskExec struct {
	Command string `xml:"Command"`

	Arguments string `xml:"Arguments"`

	WorkingDirectory string `xml:"WorkingDirectory"`
}

func collectScheduledTasks(
	ctx context.Context,
) ([]model.ScheduledTask, []string) {

	result := make(
		[]model.ScheduledTask,
		0,
	)

	warnings := make(
		[]string,
		0,
	)

	systemRoot :=
		os.Getenv(
			"SystemRoot",
		)

	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}

	root :=
		filepath.Join(
			systemRoot,
			"System32",
			"Tasks",
		)

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
								"task path %s: %v",
								path,
								err,
							),
						)

					return nil
				}

				if entry.IsDir() {
					return nil
				}

				info, infoErr :=
					entry.Info()

				relative,
					relativeErr :=
					filepath.Rel(
						root,
						path,
					)

				if relativeErr != nil {
					relative =
						entry.Name()
				}

				taskPath :=
					`\` +
						strings.ReplaceAll(
							relative,
							string(
								os.PathSeparator,
							),
							`\`,
						)

				item :=
					model.ScheduledTask{
						Name: entry.Name(),

						Path: taskPath,

						FilePath: path,
					}

				if infoErr == nil {

					item.ModifiedAt =
						info.ModTime()

					// 防御性限制。
					if info.Size() >
						8*1024*1024 {

						item.ParseError =
							"task file exceeds 8 MiB"

						result =
							append(
								result,
								item,
							)

						return nil
					}
				}

				data, readErr :=
					os.ReadFile(
						path,
					)

				if readErr != nil {

					item.ParseError =
						readErr.Error()

					result =
						append(
							result,
							item,
						)

					return nil
				}

				text, decodeErr :=
					decodeTaskFile(
						data,
					)

				if decodeErr != nil {

					item.ParseError =
						decodeErr.Error()

					result =
						append(
							result,
							item,
						)

					return nil
				}

				var parsed taskXML

				if err :=
					xml.Unmarshal(
						[]byte(text),
						&parsed,
					); err != nil {

					item.ParseError =
						err.Error()

					result =
						append(
							result,
							item,
						)

					return nil
				}

				if parsed.
					RegistrationInfo.
					URI != "" {

					item.Path =
						parsed.
							RegistrationInfo.
							URI
				}

				item.Author =
					parsed.
						RegistrationInfo.
						Author

				item.Description =
					parsed.
						RegistrationInfo.
						Description

				if len(
					parsed.Principals.Principal,
				) > 0 {

					principal :=
						parsed.
							Principals.
							Principal[0]

					item.UserID =
						principal.UserID

					item.LogonType =
						principal.LogonType

					item.RunLevel =
						principal.RunLevel
				}

				item.Enabled =
					parseOptionalBool(
						parsed.
							Settings.
							Enabled,
					)

				item.Hidden =
					parseOptionalBool(
						parsed.
							Settings.
							Hidden,
					)

				item.TriggerTypes =
					extractTaskTriggerTypes(
						text,
					)

				for _, exec := range parsed.Actions.Exec {

					item.Actions =
						append(
							item.Actions,
							model.
								ScheduledTaskAction{

								Command: strings.TrimSpace(
									exec.Command,
								),

								Arguments: strings.TrimSpace(
									exec.Arguments,
								),

								WorkingDirectory: strings.TrimSpace(
									exec.
										WorkingDirectory,
								),
							},
						)
				}

				result =
					append(
						result,
						item,
					)

				return nil
			},
		)

	if walkErr != nil {

		warnings =
			append(
				warnings,
				fmt.Sprintf(
					"walk scheduled tasks: %v",
					walkErr,
				),
			)
	}

	sort.Slice(
		result,
		func(i, j int) bool {
			return result[i].Path <
				result[j].Path
		},
	)

	return result, warnings
}

func parseOptionalBool(
	value string,
) *bool {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return nil
	}

	parsed, err :=
		strconv.ParseBool(
			value,
		)

	if err != nil {
		return nil
	}

	return &parsed
}

func decodeTaskFile(
	data []byte,
) (string, error) {

	if len(data) == 0 {
		return "", fmt.Errorf(
			"empty task file",
		)
	}

	// UTF-8 BOM
	if bytes.HasPrefix(
		data,
		[]byte{
			0xEF,
			0xBB,
			0xBF,
		},
	) {

		return string(
			data[3:],
		), nil
	}

	// UTF-16 LE BOM
	if bytes.HasPrefix(
		data,
		[]byte{
			0xFF,
			0xFE,
		},
	) {

		return decodeUTF16(
			data[2:],
			binary.LittleEndian,
		), nil
	}

	// UTF-16 BE BOM
	if bytes.HasPrefix(
		data,
		[]byte{
			0xFE,
			0xFF,
		},
	) {

		return decodeUTF16(
			data[2:],
			binary.BigEndian,
		), nil
	}

	// 某些文件可能没有 BOM，但明显为 UTF-16LE。
	if len(data) >= 4 &&
		data[1] == 0 {

		return decodeUTF16(
			data,
			binary.LittleEndian,
		), nil
	}

	return string(data), nil
}

func decodeUTF16(
	data []byte,
	order binary.ByteOrder,
) string {

	if len(data)%2 != 0 {
		data =
			data[:len(data)-1]
	}

	values :=
		make(
			[]uint16,
			len(data)/2,
		)

	for i := range values {

		values[i] =
			order.Uint16(
				data[i*2 : i*2+2],
			)
	}

	return string(
		utf16.Decode(
			values,
		),
	)
}

func extractTaskTriggerTypes(
	text string,
) []string {

	decoder :=
		xml.NewDecoder(
			strings.NewReader(
				text,
			),
		)

	result :=
		make(
			[]string,
			0,
		)

	seen :=
		make(
			map[string]struct{},
		)

	inTriggers := false
	depth := 0

	for {

		token, err :=
			decoder.Token()

		if err != nil {
			break
		}

		switch t :=
			token.(type) {

		case xml.StartElement:

			if t.Name.Local ==
				"Triggers" {

				inTriggers = true
				depth = 0
				continue
			}

			if inTriggers {

				if depth == 0 {

					name :=
						t.Name.Local

					if _, exists :=
						seen[name]; !exists {

						seen[name] =
							struct{}{}

						result =
							append(
								result,
								name,
							)
					}
				}

				depth++
			}

		case xml.EndElement:

			if !inTriggers {
				continue
			}

			if t.Name.Local ==
				"Triggers" {

				inTriggers = false
				depth = 0

				continue
			}

			if depth > 0 {
				depth--
			}
		}
	}

	return result
}
