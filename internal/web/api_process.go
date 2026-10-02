package web

import (
	"fmt"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultProcessLimit = 100
	maxProcessLimit     = 500
)

type ProcessSummary struct {
	PID uint32 `json:"pid"`

	PPID uint32 `json:"ppid"`

	Name string `json:"name"`

	Path string `json:"path,omitempty"`

	User string `json:"user,omitempty"`

	SessionID uint32 `json:"session_id,omitempty"`

	AuthenticationID string `json:"authentication_id,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`

	StartTime time.Time `json:"start_time,omitempty"`
}

type ProcessListResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	Processes []ProcessSummary `json:"processes"`
}

type ProcessDetailResponse struct {
	Process ProcessSummary `json:"process"`

	CommandLine string `json:"command_line,omitempty"`

	SHA256 string `json:"sha256,omitempty"`

	Signed bool `json:"signed"`

	Signer string `json:"signer,omitempty"`

	IntegrityRID uint32 `json:"integrity_rid,omitempty"`

	Parent *ProcessSummary `json:"parent,omitempty"`

	Children []ProcessSummary `json:"children,omitempty"`

	Relationships ProcessRelationshipSummary `json:"relationships"`
}

type ProcessRelationshipSummary struct {
	ChildCount uint32 `json:"child_count"`

	HasParent bool `json:"has_parent"`

	TimelineEventCount uint32 `json:"timeline_event_count"`
}

func processSummary(
	process model.Process,
) ProcessSummary {

	return ProcessSummary{
		PID: process.PID,

		PPID: process.PPID,

		Name: process.Name,

		Path: process.Path,

		User: process.User,

		SessionID: process.SessionID,

		AuthenticationID: process.AuthenticationID,

		IntegrityLevel: process.IntegrityLevel,

		StartTime: process.StartTime,
	}
}

func (s *Server) loadProcesses() (
	[]model.Process,
	error,
) {

	processes,
		err :=
		s.store.Processes()

	if err != nil {

		return nil,
			fmt.Errorf(
				"load process evidence: %w",
				err,
			)
	}

	return processes,
		nil
}

func (s *Server) handleProcesses(
	writer http.ResponseWriter,
	request *http.Request,
) {

	queryValues :=
		request.URL.Query()

	search :=
		strings.TrimSpace(
			queryValues.Get("q"),
		)

	user :=
		strings.TrimSpace(
			queryValues.Get("user"),
		)

	var pid uint32

	if raw :=
		strings.TrimSpace(
			queryValues.Get("pid"),
		); raw != "" {

		parsed,
			err :=
			strconv.ParseUint(
				raw,
				10,
				32,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusBadRequest,
				"invalid pid",
			)

			return
		}

		pid =
			uint32(parsed)
	}

	offset :=
		parseNonNegativeInt(
			queryValues.Get("offset"),
			0,
		)

	limit :=
		parsePositiveInt(
			queryValues.Get("limit"),
			defaultProcessLimit,
		)

	if limit >
		maxProcessLimit {

		limit =
			maxProcessLimit
	}

	result,
		err :=
		s.store.QueryProcesses(
			store.ProcessQueryOptions{
				Query: search,

				User: user,

				PID: pid,

				Page: store.QueryPageOptions{
					Offset: offset,

					Limit: limit,
				},
			},
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"query process evidence: %v",
				err,
			),
		)

		return
	}

	processes :=
		make(
			[]ProcessSummary,
			0,
			len(result.Items),
		)

	for _, process := range result.Items {

		processes =
			append(
				processes,
				processSummary(
					process,
				),
			)
	}

	writeJSON(
		writer,
		http.StatusOK,
		ProcessListResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			Processes: processes,
		},
	)
}

func (s *Server) handleProcessDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	rawPID :=
		request.PathValue(
			"pid",
		)

	parsedPID, err :=
		strconv.ParseUint(
			rawPID,
			10,
			32,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"invalid process pid",
		)

		return
	}

	pid :=
		uint32(parsedPID)

	// --------------------------------------------------
	// Selected process
	// --------------------------------------------------

	selected,
		found,
		err :=
		s.store.ProcessByPID(
			pid,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load process evidence: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"process not found",
		)

		return
	}

	// --------------------------------------------------
	// Children
	// --------------------------------------------------

	childProcesses,
		err :=
		s.store.ProcessChildren(
			pid,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load child processes: %v",
				err,
			),
		)

		return
	}

	children :=
		make(
			[]ProcessSummary,
			0,
			len(childProcesses),
		)

	for _, child := range childProcesses {

		children =
			append(
				children,
				processSummary(
					child,
				),
			)
	}

	sort.SliceStable(
		children,
		func(i, j int) bool {

			return children[i].PID <
				children[j].PID
		},
	)

	// --------------------------------------------------
	// Parent
	// --------------------------------------------------

	var parent *ProcessSummary

	if selected.PPID != 0 {

		parentProcess,
			parentFound,
			err :=
			s.store.ProcessByPID(
				selected.PPID,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusInternalServerError,
				fmt.Sprintf(
					"load parent process: %v",
					err,
				),
			)

			return
		}

		if parentFound {

			summary :=
				processSummary(
					parentProcess,
				)

			parent =
				&summary
		}
	}

	// --------------------------------------------------
	// Timeline relationship
	//
	// 暂时保留现有实现。
	// 11C-4 Timeline Store 时再迁移。
	// --------------------------------------------------

	timelineCount :=
		s.countTimelineEventsForPID(
			pid,
		)

	response :=
		ProcessDetailResponse{
			Process: processSummary(
				selected,
			),

			CommandLine: selected.CommandLine,

			SHA256: selected.SHA256,

			Signed: selected.Signed,

			Signer: selected.Signer,

			IntegrityRID: selected.IntegrityRID,

			Parent: parent,

			Children: children,

			Relationships: ProcessRelationshipSummary{
				ChildCount: uint32(
					len(children),
				),

				HasParent: parent != nil,

				TimelineEventCount: timelineCount,
			},
		}

	writeJSON(
		writer,
		http.StatusOK,
		response,
	)
}

func (s *Server) countTimelineEventsForPID(
	pid uint32,
) uint32 {

	count,
		err :=
		s.store.TimelineEventCountByPID(
			pid,
		)

	if err != nil {
		return 0
	}

	return count
}
