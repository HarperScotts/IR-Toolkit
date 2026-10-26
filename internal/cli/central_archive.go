package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"ir-toolkit/internal/store"
	"ir-toolkit/internal/store/archive"
	"ir-toolkit/internal/store/central"
)

var importRepository, importCaseID string

var centralImportCmd = &cobra.Command{
	Use:   "central-import --repository <dir> --case-id <investigation-id> <case-dir> [case-dir...]",
	Short: "Copy complete cases into an atomic, checksum-verified Central archive",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		caseID := strings.TrimSpace(importCaseID)
		if caseID == "" || strings.TrimSpace(importRepository) == "" {
			return fmt.Errorf("repository and case-id are required")
		}
		var sources []archive.Source
		for _, dir := range args {
			item, err := loadCentralView(caseID, dir)
			if err != nil {
				return err
			}
			sources = append(sources, archive.Source{View: item.View, Dir: item.Dir})
		}
		if err := archive.Commit(importRepository, sources, loadArchivedSnapshot); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Committed %d views to %s\n", len(sources), importRepository)
		return nil
	},
}

func init() {
	centralImportCmd.Flags().StringVar(&importRepository, "repository", "", "destination local archive directory")
	centralImportCmd.Flags().StringVar(&importCaseID, "case-id", "", "stable investigation ID")
	_ = centralImportCmd.MarkFlagRequired("repository")
	_ = centralImportCmd.MarkFlagRequired("case-id")
	rootCmd.AddCommand(centralImportCmd)
}

func loadArchivedSnapshot(view store.CaseView, dir string) (store.CaseStore, error) {
	item, err := loadCentralView(view.CaseID, dir)
	if err != nil {
		return nil, err
	}
	if item.View != view {
		return nil, fmt.Errorf("archive identity does not match case evidence")
	}
	return item.Store, nil
}

func openArchivedInvestigation(root, caseID string) (*central.Repository, *central.Investigator, []loadedCentralView, error) {
	all, entries, err := archive.Load(root, loadArchivedSnapshot)
	if err != nil {
		return nil, nil, nil, err
	}
	var loaded []loadedCentralView
	var selected []*central.CaseStore
	for _, entry := range entries {
		if entry.View.CaseID != caseID {
			continue
		}
		snapshot, _ := all.Open(entry.View)
		selected = append(selected, snapshot)
		loaded = append(loaded, loadedCentralView{View: entry.View, Store: snapshot, Dir: entry.Dir})
	}
	if len(loaded) == 0 {
		return nil, nil, nil, fmt.Errorf("no committed views for case %q", caseID)
	}
	sort.Slice(loaded, func(a, b int) bool {
		if loaded[a].View.HostID != loaded[b].View.HostID {
			return loaded[a].View.HostID < loaded[b].View.HostID
		}
		return loaded[a].View.Version < loaded[b].View.Version
	})
	repository, err := central.NewRepository(selected...)
	if err != nil {
		return nil, nil, nil, err
	}
	investigator, err := central.NewInvestigator(repository)
	return repository, investigator, loaded, err
}
