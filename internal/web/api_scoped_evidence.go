package web

import (
	"errors"
	"net/http"

	"ir-toolkit/internal/store"
)

func (s *Server) handleScopedEvidenceDetail(details store.ScopedEvidenceStore) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			View multiHostViewRequest `json:"view"`
			Type string               `json:"type"`
			ID   string               `json:"id"`
		}
		if err := decodeMultiHostRequest(writer, request, &input); err != nil {
			writeAPIError(writer, http.StatusBadRequest, err.Error())
			return
		}
		views, err := caseViewsFromRequest([]multiHostViewRequest{input.View})
		if err != nil || input.Type == "" || input.ID == "" {
			writeAPIError(writer, http.StatusBadRequest, "view, type and id are required")
			return
		}
		result, found, err := details.EvidenceDetail(views[0], input.Type, input.ID)
		if err != nil {
			if errors.Is(err, store.ErrInvalidEvidenceID) || errors.Is(err, store.ErrUnsupportedEvidenceType) {
				writeAPIError(writer, http.StatusBadRequest, err.Error())
				return
			}
			writeMultiHostError(writer, "load scoped evidence", err)
			return
		}
		if !found {
			writeAPIError(writer, http.StatusNotFound, "evidence not found")
			return
		}
		evidence := result.Evidence
		switch value := evidence.(type) {
		case store.NetworkQueryItem:
			evidence = networkListItemFromQueryItem(value)
		case store.PersistenceQueryItem:
			evidence = persistenceListItemFromQueryItem(value)
		}
		writeJSON(writer, http.StatusOK, struct {
			View     multiHostViewResponse `json:"view"`
			Type     string                `json:"type"`
			ID       string                `json:"id"`
			Evidence any                   `json:"evidence"`
		}{multiHostViewResponseFromStore(result.View), result.Type, result.ID, evidence})
	}
}
