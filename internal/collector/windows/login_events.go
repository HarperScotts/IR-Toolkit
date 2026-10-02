//go:build windows

package windows

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/collection"
	"ir-toolkit/internal/model"
)

const (
	defaultMaxLoginEvents = 3000

	windowedMaxLoginEvents = 20000
)

func collectWindowsLoginEvents(
	ctx context.Context,
) ([]model.LoginEvent, []string) {

	result :=
		make(
			[]model.LoginEvent,
			0,
			256,
		)

	warnings :=
		make(
			[]string,
			0,
		)

	channel, err :=
		windows.UTF16PtrFromString(
			"Security",
		)

	if err != nil {

		return result,
			[]string{
				err.Error(),
			}
	}

	window :=
		collection.TimeWindowFromContext(
			ctx,
		)

	queryText :=
		buildLoginEventQuery(
			window,
		)

	query, err :=
		windows.UTF16PtrFromString(
			queryText,
		)

	if err != nil {

		return result,
			[]string{
				err.Error(),
			}
	}

	handle, _, callErr :=
		procEvtQuery.Call(
			0,

			uintptr(
				unsafe.Pointer(
					channel,
				),
			),

			uintptr(
				unsafe.Pointer(
					query,
				),
			),

			evtQueryChannelPath|
				evtQueryReverseDirection,
		)

	if handle == 0 {

		return result,
			[]string{
				fmt.Sprintf(
					"EvtQuery Security log: %v",
					callErr,
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

	maxEvents :=
		defaultMaxLoginEvents

	if !window.Empty() {
		maxEvents =
			windowedMaxLoginEvents
	}

	for len(result) < maxEvents {

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

		var returned uint32

		r1, _, nextErr :=
			procEvtNext.Call(
				handle,

				uintptr(
					len(events),
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
				append(
					warnings,
					fmt.Sprintf(
						"EvtNext: %v",
						nextErr,
					),
				)

			break
		}

		for i := uint32(0); i < returned; i++ {

			eventHandle :=
				events[i]

			xmlText,
				err :=
				renderEventXML(
					eventHandle,
				)

			procEvtClose.Call(
				uintptr(
					eventHandle,
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

			event, err :=
				parseLoginEventXML(
					xmlText,
				)

			if err != nil {

				warnings =
					appendUniqueWarning(
						warnings,
						err.Error(),
					)

				continue
			}

			if !window.Empty() &&
				!event.Timestamp.IsZero() &&
				!window.Contains(
					event.Timestamp,
				) {

				continue
			}

			result =
				append(
					result,
					event,
				)

			if len(result) >= maxEvents {

				break
			}
		}
	}

	if len(result) >= maxEvents {

		warnings =
			appendUniqueWarning(
				warnings,
				fmt.Sprintf(
					"login event limit reached (%d); evidence may be truncated",
					maxEvents,
				),
			)
	}

	return result, warnings
}

// func renderEventXML(
// 	event windows.Handle,
// ) (string, error) {

// 	var bufferUsed uint32
// 	var propertyCount uint32

// 	// --------------------------------------------------
// 	// First call:
// 	// Ask Windows for required buffer size.
// 	//
// 	// ERROR_INSUFFICIENT_BUFFER is EXPECTED here.
// 	// --------------------------------------------------

// 	r1, _, callErr :=
// 		procEvtRender.Call(
// 			0,

// 			uintptr(
// 				event,
// 			),

// 			evtRenderEventXML,

// 			0,

// 			0,

// 			uintptr(
// 				unsafe.Pointer(
// 					&bufferUsed,
// 				),
// 			),

// 			uintptr(
// 				unsafe.Pointer(
// 					&propertyCount,
// 				),
// 			),
// 		)

// 	if r1 == 0 {

// 		if !errors.Is(
// 			callErr,
// 			windows.ERROR_INSUFFICIENT_BUFFER,
// 		) {

// 			return "",
// 				fmt.Errorf(
// 					"EvtRender size query: %w",
// 					callErr,
// 				)
// 		}
// 	}

// 	if bufferUsed == 0 {

// 		return "",
// 			fmt.Errorf(
// 				"EvtRender returned zero buffer size",
// 			)
// 	}

// 	// --------------------------------------------------
// 	// bufferUsed is BYTES.
// 	//
// 	// Event XML is UTF-16, so allocate uint16 storage.
// 	// Add one extra UTF-16 element defensively.
// 	// --------------------------------------------------

// 	charCount :=
// 		int(
// 			(bufferUsed + 1) / 2,
// 		)

// 	buffer :=
// 		make(
// 			[]uint16,
// 			charCount+1,
// 		)

// 	bufferSize :=
// 		uint32(
// 			len(buffer) * 2,
// 		)

// 	// --------------------------------------------------
// 	// Second call:
// 	// Render actual XML.
// 	// --------------------------------------------------

// 	r1, _, callErr =
// 		procEvtRender.Call(
// 			0,

// 			uintptr(
// 				event,
// 			),

// 			evtRenderEventXML,

// 			uintptr(
// 				bufferSize,
// 			),

// 			uintptr(
// 				unsafe.Pointer(
// 					&buffer[0],
// 				),
// 			),

// 			uintptr(
// 				unsafe.Pointer(
// 					&bufferUsed,
// 				),
// 			),

// 			uintptr(
// 				unsafe.Pointer(
// 					&propertyCount,
// 				),
// 			),
// 		)

// 	if r1 == 0 {

// 		return "",
// 			fmt.Errorf(
// 				"EvtRender event XML: %w",
// 				callErr,
// 			)
// 	}

// 	return windows.UTF16ToString(
// 		buffer,
// 	), nil
// }

type eventXML struct {
	System struct {
		EventID uint32 `xml:"EventID"`

		Computer string `xml:"Computer"`

		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`

	EventData struct {
		Data []eventXMLData `xml:"Data"`
	} `xml:"EventData"`
}

type eventXMLData struct {
	Name string `xml:"Name,attr"`

	Value string `xml:",chardata"`
}

func parseLoginEventXML(
	value string,
) (model.LoginEvent, error) {

	var raw eventXML

	if err := xml.Unmarshal(
		[]byte(value),
		&raw,
	); err != nil {

		return model.LoginEvent{},
			fmt.Errorf(
				"parse Security event XML: %w",
				err,
			)
	}

	data :=
		make(
			map[string]string,
			len(
				raw.EventData.Data,
			),
		)

	for _, item := range raw.EventData.Data {

		data[item.Name] =
			strings.TrimSpace(
				item.Value,
			)
	}

	event :=
		model.LoginEvent{
			EventID: raw.System.EventID,

			Computer: raw.System.Computer,

			Data: data,
		}

	if raw.System.
		TimeCreated.
		SystemTime != "" {

		if parsed, err :=
			time.Parse(
				time.RFC3339Nano,
				raw.System.
					TimeCreated.
					SystemTime,
			); err == nil {

			event.Timestamp =
				parsed.UTC()
		}
	}

	normalizeLoginEvent(
		&event,
	)

	return event, nil
}

func normalizeLoginEvent(
	event *model.LoginEvent,
) {

	data :=
		event.Data

	switch event.EventID {

	// ----------------------------------------
	// Successful logon
	// ----------------------------------------

	case 4624:

		event.Success = true

		event.User =
			data["TargetUserName"]

		event.Domain =
			data["TargetDomainName"]

		event.SourceIP =
			normalizeEventIP(
				data["IpAddress"],
			)

		event.SourcePort =
			data["IpPort"]

		event.Workstation =
			data["WorkstationName"]

		event.ProcessName =
			data["ProcessName"]

		event.AuthenticationPackage =
			data["AuthenticationPackageName"]

		event.TargetLogonID =
			data["TargetLogonId"]

		event.LogonType =
			parseUint32(
				data["LogonType"],
			)

		event.LogonTypeName =
			logonTypeName(
				event.LogonType,
			)

	// ----------------------------------------
	// Failed logon
	// ----------------------------------------

	case 4625:

		event.Success = false

		event.User =
			data["TargetUserName"]

		event.Domain =
			data["TargetDomainName"]

		event.SourceIP =
			normalizeEventIP(
				data["IpAddress"],
			)

		event.SourcePort =
			data["IpPort"]

		event.Workstation =
			data["WorkstationName"]

		event.ProcessName =
			data["ProcessName"]

		event.AuthenticationPackage =
			data["AuthenticationPackageName"]

		event.Status =
			data["Status"]

		event.SubStatus =
			data["SubStatus"]

		event.LogonType =
			parseUint32(
				data["LogonType"],
			)

		event.LogonTypeName =
			logonTypeName(
				event.LogonType,
			)

	// ----------------------------------------
	// Explicit credentials
	// ----------------------------------------

	case 4648:

		event.Success = true

		event.User =
			data["TargetUserName"]

		event.Domain =
			data["TargetDomainName"]

		event.ProcessName =
			data["ProcessName"]

		event.SourceIP =
			normalizeEventIP(
				firstNonEmpty(
					data["IpAddress"],
					data["NetworkAddress"],
				),
			)

		event.SourcePort =
			firstNonEmpty(
				data["IpPort"],
				data["NetworkPort"],
			)

		event.TargetLogonID =
			data["SubjectLogonId"]

	// ----------------------------------------
	// Special privileges assigned
	// ----------------------------------------

	case 4672:

		event.Success = true

		event.User =
			data["SubjectUserName"]

		event.Domain =
			data["SubjectDomainName"]

		event.TargetLogonID =
			data["SubjectLogonId"]

		event.Privileges =
			data["PrivilegeList"]
	}
}

func parseUint32(
	value string,
) uint32 {

	result, err :=
		strconv.ParseUint(
			strings.TrimSpace(
				value,
			),
			10,
			32,
		)

	if err != nil {
		return 0
	}

	return uint32(
		result,
	)
}

func normalizeEventIP(
	value string,
) string {

	value =
		strings.TrimSpace(
			value,
		)

	switch value {

	case "",
		"-",
		"::",
		"0.0.0.0":

		return ""
	}

	// Windows 有时会返回 IPv4-mapped IPv6。
	if strings.HasPrefix(
		value,
		"::ffff:",
	) {

		return strings.TrimPrefix(
			value,
			"::ffff:",
		)
	}

	return value
}

func firstNonEmpty(
	values ...string,
) string {

	for _, value := range values {

		if strings.TrimSpace(
			value,
		) != "" {

			return value
		}
	}

	return ""
}

func logonTypeName(
	value uint32,
) string {

	switch value {

	case 2:
		return "Interactive"

	case 3:
		return "Network"

	case 4:
		return "Batch"

	case 5:
		return "Service"

	case 7:
		return "Unlock"

	case 8:
		return "NetworkCleartext"

	case 9:
		return "NewCredentials"

	case 10:
		return "RemoteInteractive"

	case 11:
		return "CachedInteractive"

	case 12:
		return "CachedRemoteInteractive"

	case 13:
		return "CachedUnlock"

	default:

		if value == 0 {
			return ""
		}

		return fmt.Sprintf(
			"Unknown(%d)",
			value,
		)
	}
}

func appendUniqueWarning(
	warnings []string,
	message string,
) []string {

	for _, existing := range warnings {

		if existing == message {
			return warnings
		}
	}

	return append(
		warnings,
		message,
	)
}

func buildLoginEventQuery(
	window collection.TimeWindow,
) string {

	conditions :=
		[]string{
			"(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672)",
		}

	timeConditions :=
		make(
			[]string,
			0,
			2,
		)

	if window.Since != nil {

		timeConditions =
			append(
				timeConditions,
				fmt.Sprintf(
					"@SystemTime >= '%s'",
					formatEventQueryTime(
						*window.Since,
					),
				),
			)
	}

	if window.Until != nil {

		timeConditions =
			append(
				timeConditions,
				fmt.Sprintf(
					"@SystemTime <= '%s'",
					formatEventQueryTime(
						*window.Until,
					),
				),
			)
	}

	if len(timeConditions) > 0 {

		conditions =
			append(
				conditions,
				fmt.Sprintf(
					"TimeCreated[%s]",
					strings.Join(
						timeConditions,
						" and ",
					),
				),
			)
	}

	return fmt.Sprintf(
		"*[System[%s]]",
		strings.Join(
			conditions,
			" and ",
		),
	)
}

func formatEventQueryTime(
	value time.Time,
) string {

	return value.UTC().
		Format(
			"2006-01-02T15:04:05.000000000Z",
		)
}
