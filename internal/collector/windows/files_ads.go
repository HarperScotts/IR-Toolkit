//go:build windows

package windows

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/model"
)

var (
	kernel32Files = windows.
			NewLazySystemDLL(
			"kernel32.dll",
		)

	procFindFirstStream = kernel32Files.
				NewProc(
			"FindFirstStreamW",
		)

	procFindNextStream = kernel32Files.
				NewProc(
			"FindNextStreamW",
		)

	procFindCloseStream = kernel32Files.
				NewProc(
			"FindClose",
		)
)

type win32FindStreamData struct {
	StreamSize int64

	StreamName [296]uint16
}

func getAlternateDataStreams(
	path string,
) []model.AlternateDataStream {

	result :=
		make(
			[]model.AlternateDataStream,
			0,
		)

	pathPtr, err :=
		windows.UTF16PtrFromString(
			path,
		)

	if err != nil {
		return result
	}

	var data win32FindStreamData

	handle, _, _ :=
		procFindFirstStream.Call(
			uintptr(
				unsafe.Pointer(
					pathPtr,
				),
			),

			0,

			uintptr(
				unsafe.Pointer(
					&data,
				),
			),

			0,
		)

	if handle ==
		uintptr(
			windows.InvalidHandle,
		) {

		return result
	}

	defer procFindCloseStream.Call(
		handle,
	)

	for {

		name :=
			windows.UTF16ToString(
				data.StreamName[:],
			)

		// 默认::$DATA 不算 ADS。
		if name != "" &&
			!strings.EqualFold(
				name,
				"::$DATA",
			) {

			result =
				append(
					result,
					model.AlternateDataStream{
						Name: name,

						Size: data.StreamSize,
					},
				)
		}

		r1, _, _ :=
			procFindNextStream.Call(
				handle,

				uintptr(
					unsafe.Pointer(
						&data,
					),
				),
			)

		if r1 == 0 {
			break
		}
	}

	return result
}

func readZoneIdentifier(
	path string,
) string {

	zonePath :=
		path +
			`:Zone.Identifier`

	data, err :=
		os.ReadFile(
			zonePath,
		)

	if err != nil {
		return ""
	}

	value :=
		string(data)

	// 防止异常 ADS 把 Evidence 撑爆。
	if len(value) > 4096 {

		value =
			value[:4096]
	}

	return value
}
