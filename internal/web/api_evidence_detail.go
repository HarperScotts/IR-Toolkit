package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

type EvidenceDetailResponse struct {
	Type string `json:"type"`

	ID string `json:"id"`

	Title string `json:"title"`

	Subtitle string `json:"subtitle,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	User string `json:"user,omitempty"`

	IP string `json:"ip,omitempty"`

	Object string `json:"object,omitempty"`

	Description string `json:"description,omitempty"`

	Fields map[string]string `json:"fields,omitempty"`
}

func (s *Server) handleEvidenceDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	evidenceType :=
		request.URL.Query().
			Get("type")

	id :=
		request.URL.Query().
			Get("id")

	if evidenceType == "" ||
		id == "" {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"type and id are required",
		)

		return
	}

	var (
		result EvidenceDetailResponse
		found  bool
	)

	switch evidenceType {

	case "file":

		result,
			found =
			s.findFileEvidenceDetail(
				id,
			)

	case "persistence":

		result,
			found =
			s.findPersistenceEvidenceDetail(
				id,
			)

	case "windows_event":

		result,
			found =
			s.findWindowsEventEvidenceDetail(
				id,
			)

	case "powershell":

		result,
			found =
			s.findPowerShellEvidenceDetail(
				id,
			)

	case "ioc":

		result,
			found =
			s.findIOCEvidenceDetail(
				id,
			)

	default:

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"unsupported evidence type",
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"evidence not found",
		)

		return
	}

	writeJSON(
		writer,
		http.StatusOK,
		result,
	)
}

func (s *Server) findFileEvidenceDetail(
	id string,
) (
	EvidenceDetailResponse,
	bool,
) {

	finding,
		found,
		err :=
		s.store.FileFindingByID(
			id,
		)

	if err != nil ||
		!found {

		return EvidenceDetailResponse{},
			false
	}

	fields :=
		map[string]string{
			"severity": finding.Severity,

			"path": finding.Path,

			"sha256": finding.SHA256,

			"score": strconv.Itoa(
				finding.Score,
			),

			"executed": strconv.FormatBool(
				finding.Executed,
			),
		}

	if len(finding.Reasons) > 0 {

		fields["reasons"] =
			strings.Join(
				finding.Reasons,
				" | ",
			)
	}

	if len(finding.RelatedProcesses) > 0 {

		fields["related_processes"] =
			strings.Join(
				finding.RelatedProcesses,
				", ",
			)
	}

	if len(finding.Persistence) > 0 {

		fields["persistence"] =
			strings.Join(
				finding.Persistence,
				" | ",
			)
	}

	var pid uint32

	if len(finding.RelatedPIDs) == 1 {

		pid =
			finding.RelatedPIDs[0]
	}

	return EvidenceDetailResponse{
			Type: "file",

			ID: finding.ID,

			Title: finding.Title,

			Subtitle: finding.Path,

			PID: pid,

			Object: finding.Path,

			Description: strings.Join(
				finding.Reasons,
				"; ",
			),

			Fields: fields,
		},
		true
}

func (s *Server) findPersistenceEvidenceDetail(
	id string,
) (
	EvidenceDetailResponse,
	bool,
) {

	finding,
		found,
		err :=
		s.store.PersistenceFindingByID(
			id,
		)

	if err != nil ||
		!found {

		return EvidenceDetailResponse{},
			false
	}

	fields :=
		map[string]string{
			"severity": finding.Severity,

			"type": finding.Type,

			"name": finding.Name,

			"command": finding.Command,

			"executable_path": finding.ExecutablePath,

			"user": finding.User,

			"score": strconv.Itoa(
				finding.Score,
			),

			"related_process": finding.RelatedProcess,
		}

	if len(finding.Reasons) > 0 {

		fields["reasons"] =
			strings.Join(
				finding.Reasons,
				" | ",
			)
	}

	subtitle :=
		finding.Type

	if finding.Name != "" {

		if subtitle != "" {

			subtitle +=
				" · "
		}

		subtitle +=
			finding.Name
	}

	return EvidenceDetailResponse{
			Type: "persistence",

			ID: finding.ID,

			Title: finding.Title,

			Subtitle: subtitle,

			PID: finding.RelatedPID,

			User: finding.User,

			Object: firstNonEmpty(
				finding.ExecutablePath,
				finding.Command,
				finding.Name,
			),

			Description: strings.Join(
				finding.Reasons,
				"; ",
			),

			Fields: fields,
		},
		true
}

func (s *Server) findWindowsEventEvidenceDetail(
	id string,
) (
	EvidenceDetailResponse,
	bool,
) {

	activity,
		found,
		err :=
		s.store.WindowsActivityByID(
			id,
		)

	if err != nil ||
		!found {

		return EvidenceDetailResponse{},
			false
	}

	fields :=
		make(
			map[string]string,
			len(activity.Metadata)+12,
		)

	for key, value := range activity.Metadata {

		fields[key] =
			value
	}

	fields["type"] =
		activity.Type

	fields["category"] =
		activity.Category

	fields["severity"] =
		activity.Severity

	fields["definition_id"] =
		activity.DefinitionID

	fields["channel"] =
		activity.Channel

	fields["event_id"] =
		strconv.FormatUint(
			uint64(
				activity.EventID,
			),
			10,
		)

	fields["record_id"] =
		strconv.FormatUint(
			activity.RecordID,
			10,
		)

	fields["session_id"] =
		activity.SessionID

	fields["process_id"] =
		strconv.FormatUint(
			uint64(
				activity.ProcessID,
			),
			10,
		)

	fields["process"] =
		activity.Process

	if len(activity.Reasons) > 0 {

		fields["reasons"] =
			strings.Join(
				activity.Reasons,
				" | ",
			)
	}

	if len(activity.RelatedIDs) > 0 {

		fields["related_ids"] =
			strings.Join(
				activity.RelatedIDs,
				", ",
			)
	}

	return EvidenceDetailResponse{
			Type: "windows_event",

			ID: activity.ID,

			Title: activity.Type,

			Subtitle: activity.Channel,

			Timestamp: activity.Timestamp,

			PID: activity.ProcessID,

			User: activity.User,

			IP: activity.SourceIP,

			Object: activity.Object,

			Description: activity.Description,

			Fields: fields,
		},
		true
}

func (s *Server) findIOCEvidenceDetail(
	id string,
) (
	EvidenceDetailResponse,
	bool,
) {

	match,
		found,
		err :=
		s.store.IOCMatchByID(
			id,
		)

	if err != nil ||
		!found {

		return EvidenceDetailResponse{},
			false
	}

	fields :=
		map[string]string{
			"ioc_type": match.IOCType,

			"ioc_value": match.IOCValue,

			"description": match.Description,

			"match_type": match.MatchType,

			"source": match.Source,

			"object": match.Object,

			"pid": strconv.FormatUint(
				uint64(
					match.PID,
				),
				10,
			),

			"process": match.Process,

			"path": match.Path,

			"sha256": match.SHA256,

			"remote_address": match.RemoteAddress,

			"remote_port": strconv.FormatUint(
				uint64(
					match.RemotePort,
				),
				10,
			),

			"command_line": match.CommandLine,

			"persistence_type": match.PersistenceType,

			"persistence_name": match.PersistenceName,

			"related_id": match.RelatedID,
		}

	title :=
		match.IOCType

	if match.IOCValue != "" {

		if title != "" {
			title += ": "
		}

		title +=
			match.IOCValue
	}

	if title == "" {

		title =
			"IOC Match"
	}

	subtitle :=
		match.MatchType

	if match.Source != "" {

		if subtitle != "" {
			subtitle += " · "
		}

		subtitle +=
			match.Source
	}

	return EvidenceDetailResponse{
			Type: "ioc",

			ID: id,

			Title: title,

			Subtitle: subtitle,

			PID: match.PID,

			IP: match.RemoteAddress,

			Object: firstNonEmpty(
				match.Object,
				match.Path,
				match.Process,
				match.CommandLine,
				match.IOCValue,
			),

			Description: match.Description,

			Fields: fields,
		},
		true
}

func (s *Server) findPowerShellEvidenceDetail(
	id string,
) (
	EvidenceDetailResponse,
	bool,
) {

	block,
		found,
		err :=
		s.store.PowerShellScriptBlockByID(
			id,
		)

	if err != nil ||
		!found {

		return EvidenceDetailResponse{},
			false
	}

	fields :=
		map[string]string{
			"script_block_id": block.ScriptBlockID,

			"last_timestamp": formatEvidenceTime(
				block.LastTimestamp,
			),

			"process_id": strconv.FormatUint(
				uint64(
					block.ProcessID,
				),
				10,
			),

			"path": block.Path,

			"message_total": strconv.FormatUint(
				uint64(
					block.MessageTotal,
				),
				10,
			),

			"fragment_count": strconv.FormatUint(
				uint64(
					block.FragmentCount,
				),
				10,
			),

			"complete": strconv.FormatBool(
				block.Complete,
			),

			"script_sha256": block.ScriptSHA256,

			"related_historical_process_id": block.RelatedHistoricalProcessID,

			"related_process_name": block.RelatedProcessName,

			"related_command_line": block.RelatedCommandLine,

			"user": block.User,

			"logon_id": block.LogonID,

			"script_text": block.ScriptText,
		}

	title :=
		"PowerShell ScriptBlock"

	if block.ScriptBlockID != "" {

		title +=
			" " +
				block.ScriptBlockID
	}

	return EvidenceDetailResponse{
			Type: "powershell",

			ID: block.ID,

			Title: title,

			Subtitle: block.Path,

			Timestamp: block.Timestamp,

			PID: block.ProcessID,

			User: block.User,

			Object: block.ScriptBlockID,

			Description: block.ScriptText,

			Fields: fields,
		},
		true
}

func firstNonEmpty(
	values ...string,
) string {

	for _, value := range values {

		value =
			strings.TrimSpace(
				value,
			)

		if value != "" {
			return value
		}
	}

	return ""
}
