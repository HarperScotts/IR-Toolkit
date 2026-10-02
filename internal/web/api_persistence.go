package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type PersistenceListItem struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Name string `json:"name"`

	Title string `json:"title,omitempty"`

	Command string `json:"command,omitempty"`

	User string `json:"user,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	Object string `json:"object,omitempty"`

	HasFinding bool `json:"has_finding"`

	FindingID string `json:"finding_id,omitempty"`

	FindingSeverity string `json:"finding_severity,omitempty"`

	FindingTitle string `json:"finding_title,omitempty"`

	FindingScore int `json:"finding_score,omitempty"`
}

type PersistenceListResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	Items []PersistenceListItem `json:"items"`
}

type PersistenceDetailResponse struct {
	Item PersistenceListItem `json:"item"`

	Service *model.ServiceInfo `json:"service,omitempty"`

	RunKey *model.RegistryRunEntry `json:"run_key,omitempty"`

	ScheduledTask *model.ScheduledTask `json:"scheduled_task,omitempty"`

	Finding *model.PersistenceFinding `json:"finding,omitempty"`

	RelatedFiles []PersistenceFileReference `json:"related_files,omitempty"`
}

type PersistenceFileReference struct {
	Path string `json:"path"`

	Name string `json:"name,omitempty"`

	SHA256 string `json:"sha256,omitempty"`

	Relation string `json:"relation"`

	FindingID string `json:"finding_id,omitempty"`
}

func (s *Server) loadPersistenceFindingMap() map[string]model.PersistenceFinding {

	findings,
		err :=
		s.store.PersistenceFindings()

	if err != nil {

		return map[string]model.PersistenceFinding{}
	}

	return findings
}

func (s *Server) loadPersistenceItems() (
	[]PersistenceListItem,
	map[string]PersistenceListItem,
	map[string]model.PersistenceFinding,
	error,
) {

	storeItems,
		err :=
		s.store.PersistenceItems()

	if err != nil {

		return nil,
			nil,
			nil,
			err
	}

	items :=
		make(
			[]PersistenceListItem,
			0,
			len(storeItems),
		)

	byID :=
		make(
			map[string]PersistenceListItem,
		)

	findings :=
		make(
			map[string]model.PersistenceFinding,
		)

	for _, storeItem := range storeItems {

		item :=
			persistenceListItemFromQueryItem(
				storeItem,
			)

		items =
			append(
				items,
				item,
			)

		if item.ID != "" {

			byID[item.ID] =
				item
		}

		if storeItem.Finding != nil &&
			storeItem.Finding.ID != "" {

			findings[storeItem.Finding.ID] =
				*storeItem.Finding
		}
	}

	return items,
		byID,
		findings,
		nil
}

func persistenceListItemFromQueryItem(
	item store.PersistenceQueryItem,
) PersistenceListItem {

	result :=
		PersistenceListItem{
			ID: item.ID,

			Type: item.Type,

			Name: item.Name,

			Title: item.Title,

			Command: item.Command,

			User: item.User,

			Object: item.Object,

			Timestamp: item.Timestamp,

			PID: item.PID,
		}

	if item.Finding != nil {

		result.HasFinding =
			true

		result.FindingID =
			item.Finding.ID

		result.FindingSeverity =
			item.Finding.Severity

		result.FindingTitle =
			item.Finding.Title

		result.FindingScore =
			item.Finding.Score
	}

	return result
}

func (s *Server) handlePersistence(
	writer http.ResponseWriter,
	request *http.Request,
) {

	values :=
		request.URL.Query()

	query :=
		strings.TrimSpace(
			values.Get("q"),
		)

	evidenceType :=
		strings.ToLower(
			strings.TrimSpace(
				values.Get("type"),
			),
		)

	user :=
		strings.TrimSpace(
			values.Get("user"),
		)

	finding :=
		parseOptionalBoolFilter(
			values.Get("finding"),
		)

	offset,
		limit :=
		parseQueryPagination(
			values,
		)

	result,
		err :=
		s.store.QueryPersistence(
			store.PersistenceQueryOptions{
				Query: query,

				Type: evidenceType,

				User: user,

				Finding: finding,

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
				"query persistence evidence: %v",
				err,
			),
		)

		return
	}

	items :=
		make(
			[]PersistenceListItem,
			0,
			len(result.Items),
		)

	for _, item := range result.Items {

		items =
			append(
				items,
				persistenceListItemFromQueryItem(item))
	}

	writeJSON(
		writer,
		http.StatusOK,
		PersistenceListResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			Items: items,
		},
	)
}

func (s *Server) handlePersistenceDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	id :=
		strings.TrimSpace(
			request.URL.Query().
				Get("id"),
		)

	if id == "" {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"id is required",
		)

		return
	}

	// ------------------------------------------
	// Store Evidence
	// ------------------------------------------

	item,
		found,
		err :=
		s.store.PersistenceItemByID(
			id,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load persistence evidence: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"persistence evidence not found",
		)

		return
	}

	// ------------------------------------------
	// Store DTO -> Web DTO
	// ------------------------------------------

	webItem :=
		persistenceListItemFromQueryItem(
			item,
		)

	response :=
		PersistenceDetailResponse{
			Item: webItem,
		}

	// ------------------------------------------
	// Finding
	//
	// PersistenceQueryItem 已经携带精确关联的 Finding，
	// 不需要再次通过 Type + Name 查询。
	// ------------------------------------------

	if item.Finding != nil {

		copyFinding :=
			*item.Finding

		response.Finding =
			&copyFinding

		response.RelatedFiles =
			s.resolvePersistenceFiles(
				&copyFinding,
			)
	}

	// ------------------------------------------
	// Raw Persistence Evidence
	// ------------------------------------------

	switch webItem.Type {

	case "service":

		service,
			found,
			err :=
			s.store.ServiceByPersistenceID(
				webItem.ID,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusInternalServerError,
				fmt.Sprintf(
					"load service evidence: %v",
					err,
				),
			)

			return
		}

		if found {

			copyService :=
				service

			response.Service =
				&copyService
		}

	case "run_key":

		entry,
			found,
			err :=
			s.store.RunKeyByPersistenceID(
				webItem.ID,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusInternalServerError,
				fmt.Sprintf(
					"load run key evidence: %v",
					err,
				),
			)

			return
		}

		if found {

			copyEntry :=
				entry

			response.RunKey =
				&copyEntry
		}

	case "scheduled_task":

		task,
			found,
			err :=
			s.store.ScheduledTaskByPersistenceID(
				webItem.ID,
			)

		if err != nil {

			writeAPIError(
				writer,
				http.StatusInternalServerError,
				fmt.Sprintf(
					"load scheduled task evidence: %v",
					err,
				),
			)

			return
		}

		if found {

			copyTask :=
				task

			response.ScheduledTask =
				&copyTask
		}
	}

	writeJSON(
		writer,
		http.StatusOK,
		response,
	)
}

func (s *Server) resolvePersistenceFiles(
	finding *model.PersistenceFinding,
) []PersistenceFileReference {

	if finding == nil {
		return nil
	}

	targetPath :=
		strings.TrimSpace(
			finding.ExecutablePath,
		)

	if targetPath == "" {
		return nil
	}

	file,
		found,
		err :=
		s.store.FileByPath(
			targetPath,
		)

	if err != nil ||
		!found {

		return nil
	}

	return []PersistenceFileReference{
		{
			Path: file.Path,

			Name: file.Name,

			SHA256: file.SHA256,

			Relation: "persistence_finding_executable_path",

			FindingID: finding.ID,
		},
	}
}
