package web

import (
	"fmt"
	"net/http"
	"time"

	"ir-toolkit/internal/model"
)

type CaseOverview struct {
	CaseName string `json:"case_name"`

	Host model.HostInfo `json:"host"`

	Capabilities model.AuditCapabilitySnapshot `json:"capabilities"`

	SecurityProviders model.SecurityProviderSnapshot `json:"security_providers"`

	Report *model.CaseReport `json:"report,omitempty"`
}

func (s *Server) handleHealth(
	writer http.ResponseWriter,
	request *http.Request,
) {

	writeJSON(
		writer,
		http.StatusOK,
		map[string]any{
			"status": "ok",

			"time": time.Now().
				UTC(),
		},
	)
}

func (s *Server) handleCase(
	writer http.ResponseWriter,
	request *http.Request,
) {

	host,
		err :=
		s.store.Host()

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load host evidence: %v",
				err,
			),
		)

		return
	}

	capabilities,
		err :=
		s.store.Capabilities()

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load capabilities evidence: %v",
				err,
			),
		)

		return
	}

	/*
		Security Provider Discovery 属于可选/部分证据。

		读取失败不应该导致整个 Overview 失败。
	*/
	securityProviders,
		_,
		err :=
		s.store.SecurityProviders()

	if err != nil {

		securityProviders =
			model.SecurityProviderSnapshot{}
	}

	/*
		Case Report 同样属于可选分析输出。
	*/
	var report *model.CaseReport

	reportValue,
		found,
		err :=
		s.store.Report()

	if err == nil &&
		found {

		reportCopy :=
			reportValue

		report =
			&reportCopy
	}

	writeJSON(
		writer,
		http.StatusOK,
		CaseOverview{
			CaseName: s.store.CaseName(),

			Host: host,

			Capabilities: capabilities,

			SecurityProviders: securityProviders,

			Report: report,
		},
	)
}
