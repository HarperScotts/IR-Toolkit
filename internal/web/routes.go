package web

import (
	"net/http"
)

func (s *Server) routes() http.Handler {

	mux :=
		http.NewServeMux()

	// -----------------------------
	// API
	// -----------------------------

	mux.HandleFunc(
		"GET /api/health",
		s.handleHealth,
	)

	mux.HandleFunc(
		"GET /api/case",
		s.handleCase,
	)

	mux.HandleFunc(
		"GET /api/timeline",
		s.handleTimeline,
	)

	mux.HandleFunc(
		"GET /api/processes",
		s.handleProcesses,
	)

	mux.HandleFunc(
		"GET /api/processes/{pid}",
		s.handleProcessDetail,
	)

	mux.HandleFunc(
		"GET /api/processes/{pid}/context",
		s.handleProcessContext,
	)

	mux.HandleFunc(
		"GET /api/correlation",
		s.handleCorrelation,
	)

	mux.HandleFunc(
		"GET /api/search",
		s.handleInvestigationSearch,
	)

	mux.HandleFunc(
		"GET /api/evidence/detail",
		s.handleEvidenceDetail,
	)

	mux.HandleFunc(
		"GET /api/logins",
		s.handleLogins,
	)

	mux.HandleFunc(
		"GET /api/login",
		s.handleLoginDetail,
	)

	mux.HandleFunc(
		"GET /api/network",
		s.handleNetwork,
	)

	mux.HandleFunc(
		"GET /api/network/detail",
		s.handleNetworkDetail,
	)

	mux.HandleFunc(
		"GET /api/files",
		s.handleFiles,
	)

	mux.HandleFunc(
		"GET /api/file",
		s.handleFileDetail,
	)

	mux.HandleFunc(
		"GET /api/persistence",
		s.handlePersistence,
	)

	mux.HandleFunc(
		"GET /api/persistence/detail",
		s.handlePersistenceDetail,
	)

	if s.multiHostStore != nil {

		mux.HandleFunc(
			"POST /api/multi-host/search",
			s.handleMultiHostSearch,
		)

		mux.HandleFunc(
			"POST /api/multi-host/timeline",
			s.handleMultiHostTimeline,
		)
	}

	// -----------------------------
	// Embedded Web UI
	// -----------------------------

	staticHandler, err :=
		s.staticHandler()

	if err != nil {

		/*
			routes() 当前无法返回 error，
			这里故意暴露一个明确的 500 handler。
		*/

		mux.HandleFunc(
			"/",
			func(
				writer http.ResponseWriter,
				request *http.Request,
			) {

				http.Error(
					writer,
					"failed to initialize embedded web UI",
					http.StatusInternalServerError,
				)
			},
		)

	} else {

		mux.Handle(
			"/",
			staticHandler,
		)
	}

	return withSecurityHeaders(
		mux,
	)
}
