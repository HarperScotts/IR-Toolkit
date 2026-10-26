package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	localstore "ir-toolkit/internal/store/local"
)

func TestSearchEndpointReportsRealLocalLoadErrors(t *testing.T) {
	for _, failure := range []string{"missing", "malformed"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			if failure == "malformed" {
				if err := os.Mkdir(filepath.Join(root, "process"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "process", "processes.json"), []byte(`{"broken":`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := &Server{store: localstore.New(root)}
			recorder := httptest.NewRecorder()
			server.handleInvestigationSearch(recorder, httptest.NewRequest(http.MethodGet, "/api/search?q=needle&type=process", nil))
			if recorder.Code != http.StatusInternalServerError {
				t.Fatalf("load failure returned %d: %s", recorder.Code, recorder.Body.String())
			}
			var response map[string]json.RawMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response) != 1 || !strings.Contains(string(response["error"]), "processes.json") {
				t.Fatalf("failure masqueraded as a result: %s", recorder.Body.String())
			}
		})
	}
}

func TestSearchEndpointNormalNoMatchIsSuccessful(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "process"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "process", "processes.json"), []byte(`[{"pid":42,"name":"present.exe"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: localstore.New(root)}
	recorder := httptest.NewRecorder()
	server.handleInvestigationSearch(recorder, httptest.NewRequest(http.MethodGet, "/api/search?q=absent&type=process", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("no-match returned %d: %s", recorder.Code, recorder.Body.String())
	}
	var response InvestigationSearchResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Total != 0 || len(response.Results) != 0 || len(response.ByType) != 0 {
		t.Fatalf("no-match result: %+v", response)
	}
}
