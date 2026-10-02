//go:build windows

package windows

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/model"
)

var (
	wtsapi32 = windows.NewLazySystemDLL(
		"wtsapi32.dll",
	)

	procWTSEnumerateSessions = wtsapi32.NewProc(
		"WTSEnumerateSessionsW",
	)

	procWTSQuerySessionInformation = wtsapi32.NewProc(
		"WTSQuerySessionInformationW",
	)

	procWTSFreeMemory = wtsapi32.NewProc(
		"WTSFreeMemory",
	)
)

const (
	wtsUserName      = 5
	wtsDomainName    = 7
	wtsClientName    = 10
	wtsClientAddress = 14
)

type wtsSessionInfo struct {
	SessionID uint32

	WinStationName *uint16

	State uint32
}

type wtsClientAddressInfo struct {
	AddressFamily uint32

	Address [20]byte
}

func collectWindowsSessions(
	ctx context.Context,
) ([]model.LoginSession, []string) {

	result :=
		make(
			[]model.LoginSession,
			0,
		)

	warnings :=
		make(
			[]string,
			0,
		)

	var buffer uintptr
	var count uint32

	r1, _, callErr :=
		procWTSEnumerateSessions.Call(
			0,
			0,
			1,
			uintptr(
				unsafe.Pointer(
					&buffer,
				),
			),
			uintptr(
				unsafe.Pointer(
					&count,
				),
			),
		)

	if r1 == 0 {

		return result,
			[]string{
				fmt.Sprintf(
					"WTSEnumerateSessionsW: %v",
					callErr,
				),
			}
	}

	if buffer == 0 ||
		count == 0 {

		return result,
			warnings
	}

	defer procWTSFreeMemory.Call(
		buffer,
	)

	sessions :=
		unsafe.Slice(
			(*wtsSessionInfo)(
				unsafe.Pointer(
					buffer,
				),
			),
			int(count),
		)

	for _, session := range sessions {

		select {

		case <-ctx.Done():

			return result,
				append(
					warnings,
					ctx.Err().
						Error(),
				)

		default:
		}

		item :=
			model.LoginSession{
				SessionID: session.SessionID,

				State: wtsStateName(
					session.State,
				),
			}

		if session.WinStationName != nil {

			item.StationName =
				windows.
					UTF16PtrToString(
						session.
							WinStationName,
					)
		}

		item.User =
			queryWTSString(
				session.SessionID,
				wtsUserName,
			)

		item.Domain =
			queryWTSString(
				session.SessionID,
				wtsDomainName,
			)

		item.ClientName =
			queryWTSString(
				session.SessionID,
				wtsClientName,
			)

		item.ClientAddress =
			queryWTSClientAddress(
				session.SessionID,
			)

		result =
			append(
				result,
				item,
			)
	}

	return result, warnings
}
func queryWTSString(
	sessionID uint32,
	infoClass uint32,
) string {

	var buffer uintptr
	var bytesReturned uint32

	r1, _, _ :=
		procWTSQuerySessionInformation.Call(
			0,

			uintptr(
				sessionID,
			),

			uintptr(
				infoClass,
			),

			uintptr(
				unsafe.Pointer(
					&buffer,
				),
			),

			uintptr(
				unsafe.Pointer(
					&bytesReturned,
				),
			),
		)

	if r1 == 0 ||
		buffer == 0 {

		return ""
	}

	defer procWTSFreeMemory.Call(
		buffer,
	)

	return windows.UTF16PtrToString(
		(*uint16)(
			unsafe.Pointer(
				buffer,
			),
		),
	)
}

func queryWTSClientAddress(
	sessionID uint32,
) string {

	var buffer uintptr
	var bytesReturned uint32

	r1, _, _ :=
		procWTSQuerySessionInformation.Call(
			0,

			uintptr(
				sessionID,
			),

			uintptr(
				wtsClientAddress,
			),

			uintptr(
				unsafe.Pointer(
					&buffer,
				),
			),

			uintptr(
				unsafe.Pointer(
					&bytesReturned,
				),
			),
		)

	if r1 == 0 ||
		buffer == 0 {

		return ""
	}

	defer procWTSFreeMemory.Call(
		buffer,
	)

	address :=
		(*wtsClientAddressInfo)(
			unsafe.Pointer(
				buffer,
			),
		)

	switch address.AddressFamily {

	case 2: // AF_INET

		ip := net.IPv4(
			address.Address[2],
			address.Address[3],
			address.Address[4],
			address.Address[5],
		)

		if ip.IsUnspecified() {
			return ""
		}

		return ip.String()
	}

	return ""
}

func wtsStateName(
	state uint32,
) string {

	switch state {

	case 0:
		return "Active"

	case 1:
		return "Connected"

	case 2:
		return "ConnectQuery"

	case 3:
		return "Shadow"

	case 4:
		return "Disconnected"

	case 5:
		return "Idle"

	case 6:
		return "Listen"

	case 7:
		return "Reset"

	case 8:
		return "Down"

	case 9:
		return "Init"

	default:
		return fmt.Sprintf(
			"Unknown(%d)",
			state,
		)
	}
}
