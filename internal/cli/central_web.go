package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	centralstore "ir-toolkit/internal/store/central"
	localstore "ir-toolkit/internal/store/local"
	webserver "ir-toolkit/internal/web"
)

var (
	centralWebCaseID string
	centralWebListen string
)

var centralWebCmd = &cobra.Command{
	Use:   "central-web --case-id <investigation-id> <case-dir> [case-dir...]",
	Short: "Start a read-only multi-host investigation web UI",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runCentralWeb,
}

func init() {
	centralWebCmd.Flags().StringVar(
		&centralWebCaseID,
		"case-id",
		"",
		"stable investigation ID shared by all host views",
	)
	_ = centralWebCmd.MarkFlagRequired("case-id")
	centralWebCmd.Flags().StringVar(
		&centralWebListen,
		"listen",
		"127.0.0.1:8080",
		"HTTP listen address",
	)
	rootCmd.AddCommand(centralWebCmd)
}

type loadedCentralView struct {
	View  store.CaseView
	Store store.CaseStore
	Dir   string
}

func runCentralWeb(cmd *cobra.Command, args []string) error {
	caseID := strings.TrimSpace(centralWebCaseID)
	if caseID == "" {
		return fmt.Errorf("case-id is required")
	}

	repository, investigator, loaded, err := buildCentralInvestigation(caseID, args)
	if err != nil {
		return err
	}
	_ = repository

	primary, ok := repository.Open(loaded[0].View)
	if !ok {
		return fmt.Errorf("open primary central view")
	}
	server, err := webserver.NewServer(webserver.Options{
		CaseDir:        loaded[0].Dir,
		ListenAddr:     centralWebListen,
		Store:          primary,
		MultiHostStore: investigator,
	})
	if err != nil {
		return err
	}

	if centralWebListen != "127.0.0.1:8080" {
		fmt.Println()
		fmt.Println("WARNING:")
		fmt.Println("The web server may expose sensitive incident-response evidence.")
		fmt.Println("Use non-localhost listeners only on trusted networks.")
		fmt.Println()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("IR-Toolkit Central Web UI")
	fmt.Printf("Case   : %s\n", caseID)
	fmt.Printf("Views  : %d\n", len(loaded))
	for _, item := range loaded {
		fmt.Printf("  - host=%s version=%s dir=%s\n", item.View.HostID, item.View.Version, item.Dir)
	}
	fmt.Printf("Listen : http://%s\n", server.ListenAddr())
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop.")

	return server.Run(ctx)
}

func buildCentralInvestigation(
	caseID string,
	caseDirs []string,
) (*centralstore.Repository, *centralstore.Investigator, []loadedCentralView, error) {
	repository, err := centralstore.NewRepository()
	if err != nil {
		return nil, nil, nil, err
	}

	loaded := make([]loadedCentralView, 0, len(caseDirs))
	requests := make([]centralstore.IngestRequest, 0, len(caseDirs))
	for _, caseDir := range caseDirs {
		item, err := loadCentralView(caseID, caseDir)
		if err != nil {
			return nil, nil, nil, err
		}
		loaded = append(loaded, item)
		requests = append(requests, centralstore.IngestRequest{
			View:     item.View,
			Snapshot: item.Store,
		})
	}

	if _, err := repository.IngestBatch(requests...); err != nil {
		return nil, nil, nil, fmt.Errorf("publish central views: %w", err)
	}
	investigator, err := centralstore.NewInvestigator(repository)
	if err != nil {
		return nil, nil, nil, err
	}

	return repository, investigator, loaded, nil
}

func loadCentralView(caseID string, caseDir string) (loadedCentralView, error) {
	absoluteDir, err := filepath.Abs(caseDir)
	if err != nil {
		return loadedCentralView{}, fmt.Errorf("resolve case directory %q: %w", caseDir, err)
	}
	info, err := os.Stat(absoluteDir)
	if err != nil {
		return loadedCentralView{}, fmt.Errorf("open case directory %q: %w", absoluteDir, err)
	}
	if !info.IsDir() {
		return loadedCentralView{}, fmt.Errorf("case path is not a directory: %s", absoluteDir)
	}

	manifest, err := readCaseManifest(filepath.Join(absoluteDir, "manifest.json"))
	if err != nil {
		return loadedCentralView{}, fmt.Errorf("load manifest for %q: %w", absoluteDir, err)
	}
	snapshot := localstore.New(absoluteDir)
	host, err := snapshot.Host()
	if err != nil {
		return loadedCentralView{}, fmt.Errorf("load host evidence for %q: %w", absoluteDir, err)
	}
	hostID := strings.TrimSpace(host.Hostname)
	if hostID == "" {
		hostID = strings.TrimSpace(manifest.Hostname)
	}
	view := store.CaseView{
		CaseID:  strings.TrimSpace(caseID),
		HostID:  hostID,
		Version: strings.TrimSpace(manifest.CaseID),
	}
	if !view.Valid() {
		return loadedCentralView{}, fmt.Errorf("derive central view for %q: %w", absoluteDir, store.ErrInvalidCaseView)
	}
	if err := freezeCaseStore(snapshot); err != nil {
		return loadedCentralView{}, fmt.Errorf("freeze case snapshot for %q: %w", absoluteDir, err)
	}

	return loadedCentralView{View: view, Store: snapshot, Dir: absoluteDir}, nil
}

func readCaseManifest(path string) (model.Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.Manifest{}, err
	}
	defer file.Close()

	var manifest model.Manifest
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&manifest); err != nil {
		return model.Manifest{}, err
	}

	return manifest, nil
}

func freezeCaseStore(snapshot store.CaseStore) error {
	checks := []struct {
		name string
		run  func() error
	}{
		{name: "host", run: func() error { _, err := snapshot.Host(); return err }},
		{name: "capabilities", run: func() error { _, err := snapshot.Capabilities(); return err }},
		{name: "security providers", run: func() error { _, _, err := snapshot.SecurityProviders(); return err }},
		{name: "report", run: func() error { _, _, err := snapshot.Report(); return err }},
		{name: "files", run: func() error { _, err := snapshot.Files(); return err }},
		{name: "persistence", run: func() error { _, err := snapshot.PersistenceSnapshot(); return err }},
		{name: "processes", run: func() error { _, err := snapshot.Processes(); return err }},
		{name: "logins", run: func() error { _, err := snapshot.LoginAnalysis(); return err }},
		{name: "network", run: func() error { _, err := snapshot.NetworkAnalysis(); return err }},
		{name: "timeline", run: func() error { _, err := snapshot.Timeline(); return err }},
		{name: "historical processes", run: func() error { _, err := snapshot.HistoricalProcesses(); return err }},
		{name: "powershell", run: func() error { _, err := snapshot.PowerShellAnalysis(); return err }},
		{name: "windows events", run: func() error { _, err := snapshot.WindowsEventAnalysis(); return err }},
		{name: "IOC", run: func() error { _, err := snapshot.IOCScanResult(); return err }},
		{name: "correlation", run: func() error { _, err := snapshot.HistoricalCorrelation(); return err }},
	}

	for _, check := range checks {
		if err := check.run(); err != nil {
			return fmt.Errorf("load %s: %w", check.name, err)
		}
	}

	return nil
}
