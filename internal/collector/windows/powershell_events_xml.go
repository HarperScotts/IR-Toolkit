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

type powerShellEventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`

		EventID uint32 `xml:"EventID"`

		Level uint32 `xml:"Level"`

		EventRecordID uint64 `xml:"EventRecordID"`

		Computer string `xml:"Computer"`

		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`

		Correlation struct {
			ActivityID string `xml:"ActivityID,attr"`
		} `xml:"Correlation"`

		Execution struct {
			ProcessID uint32 `xml:"ProcessID,attr"`

			ThreadID uint32 `xml:"ThreadID,attr"`
		} `xml:"Execution"`
	} `xml:"System"`

	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`

			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

func parsePowerShellEventXML(
	xmlText string,
) (model.PowerShellEvent, error) {

	var raw powerShellEventXML

	if err :=
		xml.Unmarshal(
			[]byte(xmlText),
			&raw,
		); err != nil {

		return model.PowerShellEvent{},
			fmt.Errorf(
				"parse PowerShell event XML: %w",
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
		model.PowerShellEvent{
			EventID: raw.System.EventID,

			Computer: raw.System.Computer,

			Provider: raw.System.Provider.Name,

			Level: raw.System.Level,

			RecordID: raw.System.EventRecordID,

			ActivityID: raw.System.Correlation.ActivityID,

			ProcessID: raw.System.Execution.ProcessID,

			ThreadID: raw.System.Execution.ThreadID,

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

	normalizePowerShellEvent(
		&result,
		data,
	)

	return result, nil
}

func normalizePowerShellEvent(
	event *model.PowerShellEvent,
	data map[string]string,
) {

	switch event.EventID {

	case 4104:

		event.ScriptBlockText =
			data["ScriptBlockText"]

		event.ScriptBlockID =
			data["ScriptBlockId"]

		event.Path =
			data["Path"]

		event.MessageNumber =
			parsePowerShellUint32(
				data["MessageNumber"],
			)

		event.MessageTotal =
			parsePowerShellUint32(
				data["MessageTotal"],
			)

	case 4103:

		event.CommandName =
			data["CommandName"]

		event.CommandType =
			data["CommandType"]

		event.HostApplication =
			data["HostApplication"]

		event.ContextInfo =
			data["ContextInfo"]

		event.UserData =
			data["UserData"]

		event.Payload =
			data["Payload"]
	}
}

func parsePowerShellUint32(
	value string,
) uint32 {

	value =
		strings.TrimSpace(
			value,
		)

	if value == "" {
		return 0
	}

	result, err :=
		strconv.ParseUint(
			value,
			10,
			32,
		)

	if err != nil {
		return 0
	}

	return uint32(result)
}
