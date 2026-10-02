//go:build windows

package windows

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

type processEventXML struct {
	System struct {
		EventID uint32 `xml:"EventID"`

		Computer string `xml:"Computer"`

		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`

	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`

			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func parseProcessEventXML(
	xmlText string,
) (model.ProcessEvent, error) {

	var raw processEventXML

	if err :=
		xml.Unmarshal(
			[]byte(xmlText),
			&raw,
		); err != nil {

		return model.ProcessEvent{},
			fmt.Errorf(
				"parse process event XML: %w",
				err,
			)
	}

	data :=
		make(
			map[string]string,
		)

	for _, item := range raw.EventData.Data {

		data[item.Name] =
			strings.TrimSpace(
				item.Value,
			)
	}

	result :=
		model.ProcessEvent{
			EventID: raw.System.EventID,

			Computer: raw.System.Computer,

			Data: data,
		}

	if raw.System.TimeCreated.SystemTime != "" {

		value, err :=
			time.Parse(
				time.RFC3339Nano,
				raw.System.
					TimeCreated.
					SystemTime,
			)

		if err == nil {

			result.Timestamp =
				value.UTC()
		}
	}

	normalizeProcess4688(
		&result,
		data,
	)

	return result, nil
}

func normalizeProcess4688(
	event *model.ProcessEvent,
	data map[string]string,
) {

	event.SubjectUserSID =
		data["SubjectUserSid"]

	event.SubjectUserName =
		data["SubjectUserName"]

	event.SubjectDomainName =
		data["SubjectDomainName"]

	event.SubjectLogonID =
		normalizeEventLogonID(
			data["SubjectLogonId"],
		)

	event.NewProcessIDRaw =
		data["NewProcessId"]

	event.NewProcessID =
		parseWindowsEventPID(
			data["NewProcessId"],
		)

	event.NewProcessName =
		data["NewProcessName"]

	event.TokenElevationType =
		data["TokenElevationType"]

	event.ProcessIDRaw =
		data["ProcessId"]

	event.ProcessID =
		parseWindowsEventPID(
			data["ProcessId"],
		)

	event.CommandLine =
		data["CommandLine"]

	event.TargetUserSID =
		data["TargetUserSid"]

	event.TargetUserName =
		data["TargetUserName"]

	event.TargetDomainName =
		data["TargetDomainName"]

	event.TargetLogonID =
		normalizeEventLogonID(
			data["TargetLogonId"],
		)

	event.ParentProcessName =
		data["ParentProcessName"]

	event.MandatoryLabel =
		data["MandatoryLabel"]
}

func parseWindowsEventPID(
	value string,
) uint32 {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" ||
		value == "-" {

		return 0
	}

	base := 10

	number := value

	if strings.HasPrefix(
		strings.ToLower(value),
		"0x",
	) {

		base = 16

		number =
			value[2:]
	}

	parsed, err :=
		strconv.ParseUint(
			number,
			base,
			32,
		)

	if err != nil {
		return 0
	}

	return uint32(parsed)
}
