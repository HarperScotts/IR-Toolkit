//go:build windows

package windows

import (
	"context"
	"fmt"
	"sort"
	"time"

	"golang.org/x/sys/windows/registry"

	"ir-toolkit/internal/model"
)

type registryRunTarget struct {
	Hive registry.Key

	HiveName string

	Key string

	View string

	ViewFlag uint32
}

func collectRegistryRunKeys(
	ctx context.Context,
) ([]model.RegistryRunEntry, []string) {

	result := make(
		[]model.RegistryRunEntry,
		0,
	)

	warnings := make(
		[]string,
		0,
	)

	targets := []registryRunTarget{

		// HKLM 64-bit
		{
			Hive:     registry.LOCAL_MACHINE,
			HiveName: "HKLM",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			View:     "64",
			ViewFlag: registry.WOW64_64KEY,
		},

		{
			Hive:     registry.LOCAL_MACHINE,
			HiveName: "HKLM",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			View:     "64",
			ViewFlag: registry.WOW64_64KEY,
		},

		// HKLM 32-bit view
		{
			Hive:     registry.LOCAL_MACHINE,
			HiveName: "HKLM",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			View:     "32",
			ViewFlag: registry.WOW64_32KEY,
		},

		{
			Hive:     registry.LOCAL_MACHINE,
			HiveName: "HKLM",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			View:     "32",
			ViewFlag: registry.WOW64_32KEY,
		},

		// HKCU
		{
			Hive:     registry.CURRENT_USER,
			HiveName: "HKCU",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			View:     "64",
			ViewFlag: registry.WOW64_64KEY,
		},

		{
			Hive:     registry.CURRENT_USER,
			HiveName: "HKCU",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			View:     "64",
			ViewFlag: registry.WOW64_64KEY,
		},

		{
			Hive:     registry.CURRENT_USER,
			HiveName: "HKCU",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
			View:     "32",
			ViewFlag: registry.WOW64_32KEY,
		},

		{
			Hive:     registry.CURRENT_USER,
			HiveName: "HKCU",
			Key:      `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
			View:     "32",
			ViewFlag: registry.WOW64_32KEY,
		},
	}

	seen := make(
		map[string]struct{},
	)

	for _, target := range targets {

		select {

		case <-ctx.Done():
			return result,
				append(
					warnings,
					ctx.Err().Error(),
				)

		default:
		}

		key, err :=
			registry.OpenKey(
				target.Hive,
				target.Key,
				registry.QUERY_VALUE|
					target.ViewFlag,
			)

		if err != nil {

			// 不存在是正常情况。
			if err == registry.ErrNotExist {
				continue
			}

			warnings =
				append(
					warnings,
					fmt.Sprintf(
						"%s\\%s (%s-bit): %v",
						target.HiveName,
						target.Key,
						target.View,
						err,
					),
				)

			continue
		}

		names, err :=
			key.ReadValueNames(-1)

		if err != nil {

			key.Close()

			warnings =
				append(
					warnings,
					fmt.Sprintf(
						"read %s\\%s values: %v",
						target.HiveName,
						target.Key,
						err,
					),
				)

			continue
		}

		sort.Strings(names)

		var keyModifiedAt time.Time

		if info, err := key.Stat(); err == nil {
			keyModifiedAt = info.ModTime()
		}

		for _, name := range names {

			dedupeKey :=
				fmt.Sprintf(
					"%s|%s|%s|%s",
					target.HiveName,
					target.Key,
					target.View,
					name,
				)

			if _, exists :=
				seen[dedupeKey]; exists {

				continue
			}

			seen[dedupeKey] =
				struct{}{}

			entry :=
				model.RegistryRunEntry{
					Hive: target.HiveName,

					Key: target.Key,

					View: target.View,

					Name: name,

					KeyModifiedAt: keyModifiedAt,
				}

			value,
				valueType,
				err :=
				key.GetStringValue(
					name,
				)

			if err != nil {

				entry.ReadError =
					err.Error()

				result =
					append(
						result,
						entry,
					)

				continue
			}

			entry.Command =
				value

			entry.ValueType =
				registryValueTypeName(
					valueType,
				)

			if valueType ==
				registry.EXPAND_SZ {

				if expanded, err :=
					registry.ExpandString(
						value,
					); err == nil {

					entry.ExpandedCommand =
						expanded
				}
			}

			result =
				append(
					result,
					entry,
				)
		}

		key.Close()
	}

	return result, warnings
}

func registryValueTypeName(
	value uint32,
) string {

	switch value {

	case registry.SZ:
		return "REG_SZ"

	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"

	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"

	case registry.DWORD:
		return "REG_DWORD"

	case registry.QWORD:
		return "REG_QWORD"

	case registry.BINARY:
		return "REG_BINARY"

	default:
		return fmt.Sprintf(
			"TYPE_%d",
			value,
		)
	}
}
