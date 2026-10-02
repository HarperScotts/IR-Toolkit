package central

import (
	"errors"
	"testing"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

type snapshotStub struct {
	store.CaseStore

	name  string
	files store.QueryResult[store.FileQueryItem]
}

func (s *snapshotStub) CaseName() string {
	return s.name
}

func (s *snapshotStub) QueryFiles(store.FileQueryOptions) (store.QueryResult[store.FileQueryItem], error) {
	return s.files, nil
}

func TestNewValidatesViewAndSnapshot(t *testing.T) {
	valid := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	var typedNil *snapshotStub

	tests := []struct {
		name     string
		view     View
		snapshot store.CaseStore
		wantErr  error
	}{
		{name: "missing case", view: View{HostID: "host-1", Version: "version-1"}, snapshot: &snapshotStub{}, wantErr: ErrInvalidView},
		{name: "missing host", view: View{CaseID: "case-1", Version: "version-1"}, snapshot: &snapshotStub{}, wantErr: ErrInvalidView},
		{name: "missing version", view: View{CaseID: "case-1", HostID: "host-1"}, snapshot: &snapshotStub{}, wantErr: ErrInvalidView},
		{name: "nil snapshot", view: valid, wantErr: ErrNilSnapshot},
		{name: "typed nil snapshot", view: valid, snapshot: typedNil, wantErr: ErrNilSnapshot},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.view, tt.snapshot)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("New() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCatalogSelectsExactCommittedView(t *testing.T) {
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-1", Version: "version-2"}
	store1, err := New(view1, &snapshotStub{name: "snapshot-1"})
	if err != nil {
		t.Fatal(err)
	}
	store2, err := New(view2, &snapshotStub{name: "snapshot-2"})
	if err != nil {
		t.Fatal(err)
	}

	catalog, err := NewCatalog(store1, store2)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", catalog.Len())
	}

	opened, ok := catalog.Open(view1)
	if !ok || opened.CaseName() != "snapshot-1" {
		t.Fatalf("Open(view1) = %v, %v", opened, ok)
	}
	opened, ok = catalog.Open(view2)
	if !ok || opened.CaseName() != "snapshot-2" {
		t.Fatalf("Open(view2) = %v, %v", opened, ok)
	}
	if _, ok := catalog.Open(View{CaseID: "case-1", HostID: "host-2", Version: "version-1"}); ok {
		t.Fatal("Open() crossed host boundary")
	}
}

func TestCatalogRejectsInvalidEntries(t *testing.T) {
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	caseStore, err := New(view, &snapshotStub{})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewCatalog(nil); !errors.Is(err, ErrNilCaseStore) {
		t.Fatalf("NewCatalog(nil) error = %v, want %v", err, ErrNilCaseStore)
	}
	if _, err := NewCatalog(caseStore, caseStore); !errors.Is(err, ErrDuplicateView) {
		t.Fatalf("NewCatalog(duplicate) error = %v, want %v", err, ErrDuplicateView)
	}
}

func TestCaseStoreBindsViewAndDelegatesContract(t *testing.T) {
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-7"}
	wantFiles := store.QueryResult[store.FileQueryItem]{
		Total: 1,
		Items: []store.FileQueryItem{
			{Evidence: model.FileTriageItem{Path: `C:\evidence\one.exe`}},
		},
	}

	centralStore, err := New(view, &snapshotStub{name: "case-name", files: wantFiles})
	if err != nil {
		t.Fatal(err)
	}

	if centralStore.View() != view {
		t.Fatalf("View() = %+v, want %+v", centralStore.View(), view)
	}
	if centralStore.CaseName() != "case-name" {
		t.Fatalf("CaseName() = %q, want case-name", centralStore.CaseName())
	}

	gotFiles, err := centralStore.QueryFiles(store.FileQueryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if gotFiles.Total != 1 || len(gotFiles.Items) != 1 || gotFiles.Items[0].Evidence.Path != `C:\evidence\one.exe` {
		t.Fatalf("QueryFiles() = %#v, want delegated snapshot result", gotFiles)
	}
}
