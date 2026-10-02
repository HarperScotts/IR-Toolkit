package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var embeddedStatic embed.FS

func (s *Server) staticHandler() (
	http.Handler,
	error,
) {

	staticFS, err :=
		fs.Sub(
			embeddedStatic,
			"static",
		)

	if err != nil {
		return nil, err
	}

	return http.FileServer(
		http.FS(
			staticFS,
		),
	), nil
}
