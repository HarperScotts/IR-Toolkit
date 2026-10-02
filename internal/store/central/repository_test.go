package central

import (
	"errors"
	"sync"
	"testing"
)

func TestRepositoryIngestPublishesExactView(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}

	published, err := repository.Ingest(IngestRequest{
		View:     view,
		Snapshot: &snapshotStub{name: "published"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if published.View() != view {
		t.Fatalf("published view = %+v, want %+v", published.View(), view)
	}

	opened, ok := repository.Open(view)
	if !ok || opened != published || opened.CaseName() != "published" {
		t.Fatalf("Open() = %v, %v, want published view", opened, ok)
	}
	if repository.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", repository.Len())
	}
}

func TestRepositoryZeroValueCanIngest(t *testing.T) {
	var repository Repository
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}

	if _, err := repository.Ingest(IngestRequest{View: view, Snapshot: &snapshotStub{}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := repository.Open(view); !ok {
		t.Fatal("zero-value Repository did not publish view")
	}
}

func TestRepositoryIngestBatchIsAllOrNothing(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	validView := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}

	_, err = repository.IngestBatch(
		IngestRequest{View: validView, Snapshot: &snapshotStub{}},
		IngestRequest{View: View{CaseID: "case-1", HostID: "host-2"}, Snapshot: &snapshotStub{}},
	)
	if !errors.Is(err, ErrInvalidView) {
		t.Fatalf("IngestBatch() error = %v, want %v", err, ErrInvalidView)
	}
	if repository.Len() != 0 {
		t.Fatalf("repository contains %d views after rejected batch", repository.Len())
	}

	_, err = repository.IngestBatch(
		IngestRequest{View: validView, Snapshot: &snapshotStub{}},
		IngestRequest{View: validView, Snapshot: &snapshotStub{}},
	)
	if !errors.Is(err, ErrDuplicateView) {
		t.Fatalf("duplicate batch error = %v, want %v", err, ErrDuplicateView)
	}
	if repository.Len() != 0 {
		t.Fatalf("repository contains %d views after duplicate batch", repository.Len())
	}
}

func TestRepositoryNeverReplacesPublishedVersion(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	view := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	first, err := repository.Ingest(IngestRequest{View: view, Snapshot: &snapshotStub{name: "first"}})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repository.Ingest(IngestRequest{View: view, Snapshot: &snapshotStub{name: "replacement"}}); !errors.Is(err, ErrDuplicateView) {
		t.Fatalf("replacement error = %v, want %v", err, ErrDuplicateView)
	}
	opened, ok := repository.Open(view)
	if !ok || opened != first || opened.CaseName() != "first" {
		t.Fatalf("published view was replaced: %v, %v", opened, ok)
	}
}

func TestRepositoryCatalogIsPointInTime(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	view1 := View{CaseID: "case-1", HostID: "host-1", Version: "version-1"}
	view2 := View{CaseID: "case-1", HostID: "host-1", Version: "version-2"}
	if _, err := repository.Ingest(IngestRequest{View: view1, Snapshot: &snapshotStub{}}); err != nil {
		t.Fatal(err)
	}

	catalog, err := repository.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Ingest(IngestRequest{View: view2, Snapshot: &snapshotStub{}}); err != nil {
		t.Fatal(err)
	}
	if catalog.Len() != 1 || repository.Len() != 2 {
		t.Fatalf("catalog/repository lengths = %d/%d, want 1/2", catalog.Len(), repository.Len())
	}
	if _, ok := catalog.Open(view2); ok {
		t.Fatal("point-in-time catalog observed a later ingest")
	}
}

func TestRepositoryConcurrentReadersAndIngest(t *testing.T) {
	repository, err := NewRepository()
	if err != nil {
		t.Fatal(err)
	}

	const viewCount = 32
	var wait sync.WaitGroup
	for i := 0; i < viewCount; i++ {
		wait.Add(2)
		go func(index int) {
			defer wait.Done()
			view := View{CaseID: "case", HostID: "host", Version: string(rune('A' + index))}
			if _, err := repository.Ingest(IngestRequest{View: view, Snapshot: &snapshotStub{}}); err != nil {
				t.Errorf("Ingest(%d): %v", index, err)
			}
		}(i)
		go func() {
			defer wait.Done()
			_ = repository.Len()
		}()
	}
	wait.Wait()

	if repository.Len() != viewCount {
		t.Fatalf("Len() = %d, want %d", repository.Len(), viewCount)
	}
}
