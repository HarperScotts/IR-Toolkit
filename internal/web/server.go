package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"ir-toolkit/internal/store"
	localstore "ir-toolkit/internal/store/local"
)

type Server struct {
	caseDir string

	listenAddr string

	httpServer *http.Server

	store store.CaseStore

	multiHostStore store.MultiHostInvestigationStore
}

type Options struct {
	CaseDir string

	ListenAddr string

	Store store.CaseStore

	MultiHostStore store.MultiHostInvestigationStore
}

func NewServer(
	options Options,
) (*Server, error) {

	if options.CaseDir == "" {

		return nil,
			fmt.Errorf(
				"case directory is required",
			)
	}

	caseDir, err :=
		filepath.Abs(
			options.CaseDir,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"resolve case directory: %w",
				err,
			)
	}

	info, err :=
		os.Stat(
			caseDir,
		)

	if err != nil {

		return nil,
			fmt.Errorf(
				"open case directory: %w",
				err,
			)
	}

	if !info.IsDir() {

		return nil,
			fmt.Errorf(
				"case path is not a directory: %s",
				caseDir,
			)
	}
	requiredFiles :=
		[]string{
			filepath.Join(
				caseDir,
				"host",
				"host.json",
			),

			filepath.Join(
				caseDir,
				"capabilities",
				"capabilities.json",
			),
		}

	for _, path := range requiredFiles {

		if _, err :=
			os.Stat(
				path,
			); err != nil {

			return nil,
				fmt.Errorf(
					"invalid case: required evidence missing: %s",
					path,
				)
		}
	}

	listen :=
		options.ListenAddr

	if listen == "" {

		listen =
			"127.0.0.1:8080"
	}

	caseStore :=
		options.Store

	if caseStore == nil {

		caseStore =
			localstore.New(
				caseDir,
			)
	}

	server :=
		&Server{
			caseDir: caseDir,

			listenAddr: listen,

			store: caseStore,

			multiHostStore: options.MultiHostStore,
		}

	mux :=
		server.routes()

	server.httpServer =
		&http.Server{
			Addr: listen,

			Handler: mux,

			ReadHeaderTimeout: 10 * time.Second,

			ReadTimeout: 30 * time.Second,

			WriteTimeout: 30 * time.Second,

			IdleTimeout: 60 * time.Second,
		}

	return server, nil
}

func (s *Server) CaseDir() string {
	return s.caseDir
}

func (s *Server) ListenAddr() string {
	return s.listenAddr
}

func (s *Server) Run(
	ctx context.Context,
) error {

	listener, err :=
		net.Listen(
			"tcp",
			s.listenAddr,
		)

	if err != nil {

		return fmt.Errorf(
			"listen on %s: %w",
			s.listenAddr,
			err,
		)
	}

	errChannel :=
		make(
			chan error,
			1,
		)

	go func() {

		err :=
			s.httpServer.
				Serve(
					listener,
				)

		if err != nil &&
			err != http.ErrServerClosed {

			errChannel <- err

			return
		}

		errChannel <- nil
	}()

	select {

	case <-ctx.Done():

		shutdownCtx,
			cancel :=
			context.WithTimeout(
				context.Background(),
				5*time.Second,
			)

		defer cancel()

		if err :=
			s.httpServer.
				Shutdown(
					shutdownCtx,
				); err != nil {

			return fmt.Errorf(
				"shutdown web server: %w",
				err,
			)
		}

		return nil

	case err :=
		<-errChannel:

		if err != nil {

			return fmt.Errorf(
				"web server: %w",
				err,
			)
		}

		return nil
	}
}
