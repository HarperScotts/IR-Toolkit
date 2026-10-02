//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	evtQueryChannelPath = 0x1

	evtQueryReverseDirection = 0x200

	evtRenderEventXML = 1
)

var (
	wevtapi = windows.NewLazySystemDLL(
		"wevtapi.dll",
	)

	procEvtQuery = wevtapi.NewProc(
		"EvtQuery",
	)

	procEvtNext = wevtapi.NewProc(
		"EvtNext",
	)

	procEvtRender = wevtapi.NewProc(
		"EvtRender",
	)

	procEvtClose = wevtapi.NewProc(
		"EvtClose",
	)
)

func queryEventXML(
	ctx context.Context,
	channel string,
	queryText string,
	maxEvents int,
) ([]string, []string) {

	result :=
		make(
			[]string,
			0,
		)

	warnings :=
		make(
			[]string,
			0,
		)

	channelPtr, err :=
		windows.UTF16PtrFromString(
			channel,
		)

	if err != nil {

		return result,
			[]string{
				fmt.Sprintf(
					"channel path: %v",
					err,
				),
			}
	}

	queryPtr, err :=
		windows.UTF16PtrFromString(
			queryText,
		)

	if err != nil {

		return result,
			[]string{
				fmt.Sprintf(
					"event query: %v",
					err,
				),
			}
	}

	handle, _, queryErr :=
		procEvtQuery.Call(
			0,

			uintptr(
				unsafe.Pointer(
					channelPtr,
				),
			),

			uintptr(
				unsafe.Pointer(
					queryPtr,
				),
			),

			evtQueryChannelPath|
				evtQueryReverseDirection,
		)

	if handle == 0 {

		return result,
			[]string{
				fmt.Sprintf(
					"EvtQuery: %v",
					queryErr,
				),
			}
	}

	defer procEvtClose.Call(
		handle,
	)

	const batchSize = 32

	events :=
		make(
			[]windows.Handle,
			batchSize,
		)

	for len(result) < maxEvents {

		select {

		case <-ctx.Done():

			return result,
				appendUniqueWarning(
					warnings,
					ctx.Err().Error(),
				)

		default:
		}

		var returned uint32

		r1, _, nextErr :=
			procEvtNext.Call(
				handle,

				uintptr(
					batchSize,
				),

				uintptr(
					unsafe.Pointer(
						&events[0],
					),
				),

				0,

				0,

				uintptr(
					unsafe.Pointer(
						&returned,
					),
				),
			)

		if r1 == 0 {

			if errors.Is(
				nextErr,
				windows.ERROR_NO_MORE_ITEMS,
			) {

				break
			}

			warnings =
				appendUniqueWarning(
					warnings,
					fmt.Sprintf(
						"EvtNext: %v",
						nextErr,
					),
				)

			break
		}

		for i := uint32(0); i < returned; i++ {

			event :=
				events[i]

			xmlText, err :=
				renderEventXML(
					event,
				)

			procEvtClose.Call(
				uintptr(
					event,
				),
			)

			if err != nil {

				warnings =
					appendUniqueWarning(
						warnings,
						err.Error(),
					)

				continue
			}

			result =
				append(
					result,
					xmlText,
				)

			if len(result) >=
				maxEvents {

				break
			}
		}
	}

	if len(result) >= maxEvents {

		warnings =
			appendUniqueWarning(
				warnings,
				fmt.Sprintf(
					"event limit reached (%d); evidence may be truncated",
					maxEvents,
				),
			)
	}

	return result, warnings
}

func renderEventXML(
	event windows.Handle,
) (string, error) {

	var bufferUsed uint32

	var propertyCount uint32

	r1, _, callErr :=
		procEvtRender.Call(
			0,

			uintptr(
				event,
			),

			evtRenderEventXML,

			0,

			0,

			uintptr(
				unsafe.Pointer(
					&bufferUsed,
				),
			),

			uintptr(
				unsafe.Pointer(
					&propertyCount,
				),
			),
		)

	if r1 == 0 {

		if !errors.Is(
			callErr,
			windows.ERROR_INSUFFICIENT_BUFFER,
		) {

			return "",
				fmt.Errorf(
					"EvtRender size query: %w",
					callErr,
				)
		}
	}

	if bufferUsed == 0 {

		return "",
			fmt.Errorf(
				"EvtRender returned zero buffer size",
			)
	}

	charCount :=
		int(
			(bufferUsed + 1) / 2,
		)

	buffer :=
		make(
			[]uint16,
			charCount+1,
		)

	bufferSize :=
		uint32(
			len(buffer) * 2,
		)

	r1, _, callErr =
		procEvtRender.Call(
			0,

			uintptr(
				event,
			),

			evtRenderEventXML,

			uintptr(
				bufferSize,
			),

			uintptr(
				unsafe.Pointer(
					&buffer[0],
				),
			),

			uintptr(
				unsafe.Pointer(
					&bufferUsed,
				),
			),

			uintptr(
				unsafe.Pointer(
					&propertyCount,
				),
			),
		)

	if r1 == 0 {

		return "",
			fmt.Errorf(
				"EvtRender event XML: %w",
				callErr,
			)
	}

	return windows.UTF16ToString(
		buffer,
	), nil
}
