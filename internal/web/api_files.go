package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type FileListItem struct {
	Path string `json:"path"`

	Name string `json:"name"`

	Extension string `json:"extension,omitempty"`

	Size int64 `json:"size"`

	CreatedAt time.Time `json:"created_at,omitempty"`

	ModifiedAt time.Time `json:"modified_at,omitempty"`

	AccessedAt time.Time `json:"accessed_at,omitempty"`

	Owner string `json:"owner,omitempty"`

	Executable bool `json:"executable"`

	SHA256 string `json:"sha256,omitempty"`

	ADS []model.AlternateDataStream `json:"ads,omitempty"`

	ZoneIdentifier string `json:"zone_identifier,omitempty"`

	Source string `json:"source"`

	/*
	 * Analyzer Finding Context
	 */
	HasFinding bool `json:"has_finding"`

	FindingID string `json:"finding_id,omitempty"`

	FindingSeverity string `json:"finding_severity,omitempty"`

	FindingTitle string `json:"finding_title,omitempty"`

	FindingScore int `json:"finding_score,omitempty"`
}

type FileListResponse struct {
	Total uint32 `json:"total"`

	Offset uint32 `json:"offset"`

	Limit uint32 `json:"limit"`

	HasMore bool `json:"has_more"`

	Files []FileListItem `json:"files"`
}

type FileDetailResponse struct {
	File FileListItem `json:"file"`

	Finding *model.FileFinding `json:"finding,omitempty"`

	RelatedPersistence []FilePersistenceReference `json:"related_persistence,omitempty"`
}

type FilePersistenceReference struct {
	ID string `json:"id"`

	Type string `json:"type"`

	Name string `json:"name"`

	Title string `json:"title,omitempty"`

	Relation string `json:"relation"`

	FindingID string `json:"finding_id,omitempty"`
}

func (s *Server) loadFileFindingMap() map[string]model.FileFinding {

	findings,
		err :=
		s.store.FileFindings()

	if err != nil {

		return map[string]model.FileFinding{}
	}

	return findings
}

func normalizeFileEvidencePath(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}

func fileListItemFromEvidence(
	file model.FileTriageItem,
	findingMap map[string]model.FileFinding,
) FileListItem {

	item :=
		FileListItem{
			Path: file.Path,

			Name: file.Name,

			Extension: file.Extension,

			Size: file.Size,

			CreatedAt: file.CreatedAt,

			ModifiedAt: file.ModifiedAt,

			AccessedAt: file.AccessedAt,

			Owner: file.Owner,

			Executable: file.Executable,

			SHA256: file.SHA256,

			ADS: file.ADS,

			ZoneIdentifier: file.ZoneIdentifier,

			Source: file.Source,
		}

	finding,
		ok :=
		findingMap[normalizeFileEvidencePath(
			file.Path,
		)]

	if !ok {
		return item
	}

	item.HasFinding =
		true

	item.FindingID =
		finding.ID

	item.FindingSeverity =
		finding.Severity

	item.FindingTitle =
		finding.Title

	item.FindingScore =
		finding.Score

	return item
}

func fileListItemFromQueryItem(
	item store.FileQueryItem,
) FileListItem {

	findingMap :=
		map[string]model.FileFinding{}

	if item.Finding != nil {

		findingMap[normalizeFileEvidencePath(
			item.Evidence.Path,
		)] =
			*item.Finding
	}

	return fileListItemFromEvidence(
		item.Evidence,
		findingMap,
	)
}

func (s *Server) handleFiles(
	writer http.ResponseWriter,
	request *http.Request,
) {

	values :=
		request.URL.Query()

	query :=
		strings.TrimSpace(
			values.Get("q"),
		)

	owner :=
		strings.TrimSpace(
			values.Get("owner"),
		)

	extension :=
		strings.TrimSpace(
			values.Get("extension"),
		)

	executable :=
		parseOptionalBoolFilter(
			values.Get("executable"),
		)

	finding :=
		parseOptionalBoolFilter(
			values.Get("finding"),
		)

	offset, limit := parseQueryPagination(values)

	result,
		err :=
		s.store.QueryFiles(
			store.FileQueryOptions{
				Query: query,

				Owner: owner,

				Extension: extension,

				Executable: executable,

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
				"query file evidence: %v",
				err,
			),
		)

		return
	}

	files :=
		make(
			[]FileListItem,
			0,
			len(result.Items),
		)

	for _, item := range result.Items {

		files =
			append(
				files,
				fileListItemFromQueryItem(
					item,
				),
			)
	}

	writeJSON(
		writer,
		http.StatusOK,
		FileListResponse{
			Total: result.Total,

			Offset: uint32(
				result.Page.Offset,
			),

			Limit: uint32(
				result.Page.Limit,
			),

			HasMore: result.Page.HasMore,

			Files: files,
		},
	)
}

func (s *Server) handleFileDetail(
	writer http.ResponseWriter,
	request *http.Request,
) {

	targetPath :=
		strings.TrimSpace(
			request.URL.Query().
				Get("path"),
		)

	if targetPath == "" {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"path is required",
		)

		return
	}

	file,
		found,
		err :=
		s.store.FileByPath(
			targetPath,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load file evidence: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"file evidence not found",
		)

		return
	}

	finding,
		hasFinding,
		err :=
		s.store.FileFindingByPath(
			file.Path,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load file finding: %v",
				err,
			),
		)

		return
	}

	findingMap :=
		s.loadFileFindingMap()

	item :=
		fileListItemFromEvidence(
			file,
			findingMap,
		)

	var findingPointer *model.FileFinding

	if hasFinding {

		copyFinding :=
			finding

		findingPointer =
			&copyFinding
	}

	relatedPersistence :=
		s.resolveFilePersistenceReferences(
			findingPointer,
		)

	writeJSON(
		writer,
		http.StatusOK,
		FileDetailResponse{
			File: item,

			Finding: findingPointer,

			RelatedPersistence: relatedPersistence,
		},
	)
}

func (s *Server) resolveFilePersistenceReferences(
	finding *model.FileFinding,
) []FilePersistenceReference {

	if finding == nil ||
		len(finding.Persistence) == 0 {

		return nil
	}

	items,
		_,
		findings,
		err :=
		s.loadPersistenceItems()

	if err != nil {
		return nil
	}

	/*
	 * 只建立精确 ID 索引。
	 *
	 * 不使用 contains / path similarity /
	 * command similarity 等模糊关系。
	 */
	byEvidenceID :=
		make(
			map[string]PersistenceListItem,
		)

	for _, item := range items {

		byEvidenceID[strings.ToLower(
			strings.TrimSpace(
				item.ID,
			),
		)] =
			item
	}

	byFindingID :=
		make(
			map[string]model.PersistenceFinding,
		)

	for _, persistenceFinding := range findings {

		byFindingID[strings.ToLower(
			strings.TrimSpace(
				persistenceFinding.ID,
			),
		)] =
			persistenceFinding
	}

	results :=
		make(
			[]FilePersistenceReference,
			0,
		)

	seen :=
		make(
			map[string]bool,
		)

	for _, rawReference := range finding.Persistence {

		reference :=
			strings.ToLower(
				strings.TrimSpace(
					rawReference,
				),
			)

		if reference == "" {
			continue
		}

		/*
		 * FileFinding.Persistence 如果保存的是
		 * Full Persistence Evidence ID。
		 */
		if item, ok :=
			byEvidenceID[reference]; ok {

			if !seen[item.ID] {

				results =
					append(
						results,
						FilePersistenceReference{
							ID: item.ID,

							Type: item.Type,

							Name: item.Name,

							Title: item.Title,

							Relation: "file_finding_persistence_reference",

							FindingID: finding.ID,
						},
					)

				seen[item.ID] =
					true
			}

			continue
		}

		/*
		 * FileFinding.Persistence 如果保存的是
		 * PersistenceFinding.ID。
		 */
		persistenceFinding,
			ok :=
			byFindingID[reference]

		if !ok {
			continue
		}

		for _, item := range items {

			if !strings.EqualFold(
				item.Type,
				persistenceFinding.Type,
			) ||
				!strings.EqualFold(
					item.Name,
					persistenceFinding.Name,
				) {

				continue
			}

			if seen[item.ID] {
				continue
			}

			results =
				append(
					results,
					FilePersistenceReference{
						ID: item.ID,

						Type: item.Type,

						Name: item.Name,

						Title: item.Title,

						Relation: "file_finding_persistence_reference",

						FindingID: persistenceFinding.ID,
					},
				)

			seen[item.ID] =
				true
		}
	}

	return results
}

func parseOptionalBoolFilter(
	value string,
) *bool {

	switch strings.ToLower(
		strings.TrimSpace(
			value,
		),
	) {

	case "true", "1", "yes":

		result :=
			true

		return &result

	case "false", "0", "no":

		result :=
			false

		return &result
	}

	return nil
}
