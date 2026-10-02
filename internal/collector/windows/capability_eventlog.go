//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/model"
)

func checkEventChannel(
	channel string,
) model.CapabilityStatus {

	channelPtr, err :=
		windows.UTF16PtrFromString(
			channel,
		)

	if err != nil {

		return model.CapabilityStatus{
			Status: "error",

			Reason: err.Error(),
		}
	}

	queryPtr, err :=
		windows.UTF16PtrFromString(
			"*",
		)

	if err != nil {

		return model.CapabilityStatus{
			Status: "error",

			Reason: err.Error(),
		}
	}

	handle,
		_,
		callErr :=
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

			evtQueryChannelPath,
		)

	if handle == 0 {

		return model.CapabilityStatus{
			Available: false,

			Enabled: false,

			Status: "unavailable",

			Reason: fmt.Sprintf(
				"event channel unavailable: %v",
				callErr,
			),
		}
	}

	procEvtClose.Call(
		handle,
	)

	return model.CapabilityStatus{
		Available: true,

		Enabled: true,

		Status: "available",
	}
}
