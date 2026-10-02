//go:build windows

package windows

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

type genericWindowsEventXML struct {
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

		Security struct {
			UserID string `xml:"UserID,attr"`
		} `xml:"Security"`
	} `xml:"System"`

	EventData struct {
		Data []struct {
			Name string `xml:"Name,attr"`

			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`

	UserData struct {
		InnerXML string `xml:",innerxml"`
	} `xml:"UserData"`
}

func parseGenericWindowsEventXML(
	xmlText string,
	definitionID string,
	channel string,
) (
	model.WindowsEvent,
	error,
) {

	var raw genericWindowsEventXML

	if err :=
		xml.Unmarshal(
			[]byte(xmlText),
			&raw,
		); err != nil {

		return model.WindowsEvent{},
			fmt.Errorf(
				"parse %s event XML: %w",
				definitionID,
				err,
			)
	}

	data :=
		make(
			map[string]string,
		)

	for index, item := range raw.EventData.Data {

		key :=
			strings.TrimSpace(
				item.Name,
			)

		if key == "" {

			key =
				fmt.Sprintf(
					"Data%d",
					index,
				)
		}

		data[key] =
			strings.TrimSpace(
				item.Value,
			)
	}

	result :=
		model.WindowsEvent{
			DefinitionID: definitionID,

			Channel: channel,

			Provider: raw.System.Provider.Name,

			EventID: raw.System.EventID,

			RecordID: raw.System.EventRecordID,

			Level: raw.System.Level,

			Computer: raw.System.Computer,

			ProcessID: raw.System.Execution.ProcessID,

			ThreadID: raw.System.Execution.ThreadID,

			ActivityID: raw.System.Correlation.ActivityID,

			UserID: raw.System.Security.UserID,

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

	if strings.TrimSpace(
		raw.UserData.InnerXML,
	) != "" {

		result.UserData =
			map[string]string{
				"raw_xml": raw.UserData.InnerXML,
			}
	}

	return result, nil
}
