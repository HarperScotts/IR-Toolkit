package central

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

// Walk every method's input/output type, not a hand-maintained list of models.
// New mutable kinds, private fields or recursive data require an explicit copy
// design rather than silently exposing shared storage.
func populatedSnapshotValue(t *testing.T, kind reflect.Type, active map[reflect.Type]bool) reflect.Value {
	t.Helper()
	if kind == snapshotTimeType {
		return reflect.ValueOf(time.Now())
	}
	if active[kind] {
		t.Fatalf("recursive snapshot type needs explicit copy support: %v", kind)
	}
	active[kind] = true
	defer delete(active, kind)
	value := reflect.New(kind).Elem()
	switch kind.Kind() {
	case reflect.Pointer:
		value.Set(reflect.New(kind.Elem()))
		value.Elem().Set(populatedSnapshotValue(t, kind.Elem(), active))
	case reflect.Slice:
		value.Set(reflect.MakeSlice(kind, 1, 1))
		value.Index(0).Set(populatedSnapshotValue(t, kind.Elem(), active))
	case reflect.Array:
		for index := 0; index < value.Len(); index++ {
			value.Index(index).Set(populatedSnapshotValue(t, kind.Elem(), active))
		}
	case reflect.Map:
		value.Set(reflect.MakeMap(kind))
		value.SetMapIndex(populatedSnapshotValue(t, kind.Key(), active), populatedSnapshotValue(t, kind.Elem(), active))
	case reflect.Struct:
		for index := 0; index < kind.NumField(); index++ {
			if !kind.Field(index).IsExported() {
				t.Fatalf("private snapshot field needs explicit copy support: %v.%s", kind, kind.Field(index).Name)
			}
			value.Field(index).Set(populatedSnapshotValue(t, kind.Field(index).Type, active))
		}
	case reflect.String:
		value.SetString("original")
	case reflect.Bool:
		value.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(7)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		value.SetUint(7)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(7)
	default:
		t.Fatalf("unsupported snapshot field type: %v", kind)
	}
	return value
}

func mutateSnapshotValue(value reflect.Value) {
	if value.Type() == snapshotTimeType {
		value.Set(reflect.ValueOf(time.Time{}))
		return
	}
	switch value.Kind() {
	case reflect.Pointer:
		if !value.IsNil() {
			mutateSnapshotValue(value.Elem())
		}
	case reflect.Slice, reflect.Array:
		for index := 0; index < value.Len(); index++ {
			mutateSnapshotValue(value.Index(index))
		}
	case reflect.Map:
		value.Clear()
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			mutateSnapshotValue(value.Field(index))
		}
	default:
		value.Set(reflect.Zero(value.Type()))
	}
}

func TestSnapshotCopySupportsEntireStoreContract(t *testing.T) {
	contract := reflect.TypeFor[store.CaseStore]()
	for index := 0; index < contract.NumMethod(); index++ {
		method := contract.Method(index)
		t.Run(method.Name, func(t *testing.T) {
			var types []reflect.Type
			for index := 0; index < method.Type.NumIn(); index++ {
				types = append(types, method.Type.In(index))
			}
			for index := 0; index < method.Type.NumOut(); index++ {
				if kind := method.Type.Out(index); kind != reflect.TypeFor[error]() {
					types = append(types, kind)
				}
			}
			for _, kind := range types {
				original := populatedSnapshotValue(t, kind, map[reflect.Type]bool{})
				baseline, err := json.Marshal(original.Interface())
				if err != nil {
					t.Fatal(err)
				}
				copied := reflect.New(kind).Elem()
				copied.Set(copySnapshotReflect(original))
				if !reflect.DeepEqual(original.Interface(), copied.Interface()) {
					t.Fatalf("copy changed %v", kind)
				}
				mutateSnapshotValue(copied)
				after, err := json.Marshal(original.Interface())
				if err != nil || !bytes.Equal(after, baseline) {
					t.Fatalf("caller mutation reached original %v", kind)
				}
				zero := reflect.Zero(kind)
				if !reflect.DeepEqual(zero.Interface(), copySnapshotReflect(zero).Interface()) {
					t.Fatalf("copy changed nil/zero semantics for %v", kind)
				}
			}
		})
	}
}

type ownedSnapshotStub struct {
	store.CaseStore
	timeline *model.Timeline
	files    store.QueryResult[store.FileQueryItem]
	search   store.InvestigationSearchStoreResult
	err      error
}

func (s *ownedSnapshotStub) Timeline() (*model.Timeline, error) { return s.timeline, s.err }
func (s *ownedSnapshotStub) TimelineEventByID(string) (model.TimelineEvent, bool, error) {
	return s.timeline.Events[0], true, s.err
}
func (s *ownedSnapshotStub) QueryFiles(store.FileQueryOptions) (store.QueryResult[store.FileQueryItem], error) {
	return s.files, s.err
}
func (s *ownedSnapshotStub) SearchInvestigation(options store.InvestigationSearchOptions) (store.InvestigationSearchStoreResult, error) {
	// A backend must not be able to modify the caller's filter map either.
	delete(options.Types, "timeline")
	return s.search, s.err
}

func TestPublishedResultsAreCallerOwned(t *testing.T) {
	source := &ownedSnapshotStub{
		timeline: &model.Timeline{Events: []model.TimelineEvent{{ID: "event:1", RelatedIDs: []string{"history:1"}, Metadata: map[string]string{"origin": "original"}}}},
		files:    store.QueryResult[store.FileQueryItem]{Items: []store.FileQueryItem{{Finding: &model.FileFinding{Reasons: []string{"original"}}}}},
		search:   store.InvestigationSearchStoreResult{ByType: map[string]uint32{"timeline": 1}, Items: []store.InvestigationSearchItem{{Metadata: map[string]string{"origin": "original"}}}},
	}
	repository, _ := NewRepository()
	view := View{CaseID: "case", HostID: "host", Version: "1"}
	published, err := repository.Ingest(IngestRequest{View: view, Snapshot: source})
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := repository.Catalog()
	fromCatalog, _ := catalog.Open(view)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 20 {
				timeline, _ := published.Timeline()
				timeline.Events[0].ID = "changed"
				timeline.Events[0].RelatedIDs[0] = "changed"
				timeline.Events[0].Metadata["origin"] = "changed"
				files, _ := fromCatalog.QueryFiles(store.FileQueryOptions{})
				files.Items[0].Finding.Reasons[0] = "changed"
			}
		})
	}
	workers.Wait()
	event, found, err := published.TimelineEventByID("event:1")
	if err != nil || !found || event.ID != "event:1" || event.RelatedIDs[0] != "history:1" || event.Metadata["origin"] != "original" {
		t.Fatalf("published detail was mutated: %+v, %v", event, err)
	}
	files, _ := published.QueryFiles(store.FileQueryOptions{})
	if files.Items[0].Finding.Reasons[0] != "original" {
		t.Fatal("nested finding was mutated")
	}
	options := store.InvestigationSearchOptions{Types: map[string]bool{"timeline": true}}
	search, _ := published.SearchInvestigation(options)
	search.ByType["timeline"] = 99
	search.Items[0].Metadata["origin"] = "changed"
	if !options.Types["timeline"] || source.search.ByType["timeline"] != 1 || source.search.Items[0].Metadata["origin"] != "original" {
		t.Fatal("Search input/output maps share ownership")
	}
}

func TestSnapshotCopyPreservesErrorsAndOptionalData(t *testing.T) {
	wantErr := errors.New("storage failure")
	published, _ := New(View{CaseID: "case", HostID: "host", Version: "1"}, &ownedSnapshotStub{err: wantErr})
	timeline, err := published.Timeline()
	if timeline != nil || err != wantErr {
		t.Fatalf("nil/error changed: %v, %v", timeline, err)
	}
	empty := copySnapshotValue([]model.TimelineEvent{})
	if empty == nil || len(empty) != 0 {
		t.Fatal("empty slice became nil")
	}
}
