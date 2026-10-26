package packageio

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestExtractRoundTripAndCleanup(t *testing.T) {
	source, original := exportFixture(t)
	var data bytes.Buffer
	exported, err := ExportCase(context.Background(), source, "display / not-a-directory", &data, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	keep := filepath.Join(parent, "keep.json")
	if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	extracted, err := Extract(context.Background(), bytes.NewReader(data.Bytes()), parent, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer extracted.Close()
	if !reflect.DeepEqual(extracted.Verification, exported) || filepath.Base(extracted.CaseDir()) != "case" {
		t.Fatalf("extraction result: %+v", extracted)
	}
	for name, expected := range original {
		path := filepath.Join(extracted.CaseDir(), filepath.FromSlash(name))
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("raw bytes changed for %q: %v", name, err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("not a regular payload: %q %v", name, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("file permissions: %v", info.Mode())
		}
	}
	for _, directory := range []string{extracted.root, extracted.CaseDir(), filepath.Join(extracted.CaseDir(), "analysis")} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
			t.Fatalf("directory permissions: %v", info.Mode())
		}
	}
	if _, err := os.Lstat(filepath.Join(extracted.CaseDir(), "package.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("descriptor extracted as evidence")
	}
	root := extracted.root
	if err := extracted.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extracted.Close(); err != nil {
		t.Fatal("Close is not idempotent", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary root retained: %v", err)
	}
	if contents, err := os.ReadFile(keep); err != nil || string(contents) != "keep" {
		t.Fatal("cleanup touched parent contents")
	}
	for name, expected := range original {
		actual, err := os.ReadFile(filepath.Join(source, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("extraction changed source case")
		}
	}
}

func TestExtractFailuresRemoveOnlyOwnedTree(t *testing.T) {
	data := sourceFixture(t, `{"case_id":"collection-1","files":null}`, `{"hostname":"alpha"}`)
	_, _, first := containerFixture(t, []containerEntry{
		{"case/host/host.json", []byte(`{"hostname":"alpha"}`)},
		{"case/manifest.json", []byte(`{"case_id":"collection-1","files":null}`)},
		{"case/raw/evidence.json", []byte("evidence")},
	})
	mutate := func(change func([]byte)) []byte { copy := bytes.Clone(data); change(copy); return copy }
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrInvalidContainer},
		{"truncated header", data[:first+20], ErrInvalidContainer},
		{"truncated body", data[:first+512+3], ErrInvalidContainer},
		{"truncated terminator", data[:len(data)-1], ErrInvalidContainer},
		{"extra byte", append(bytes.Clone(data), 1), ErrInvalidContainer},
		{"concatenated", append(bytes.Clone(data), data...), ErrInvalidContainer},
		{"hash mismatch", mutate(func(raw []byte) { raw[first+512+1] ^= 1 }), ErrPayloadMismatch},
		{"padding", mutate(func(raw []byte) { raw[first+512+len(`{"hostname":"alpha"}`)] = 1 }), ErrInvalidContainer},
		{"link header", mutate(func(raw []byte) { raw[first+156] = tar.TypeSymlink; fixHeaderChecksum(raw[first : first+512]) }), ErrInvalidContainer},
		{"directory header", mutate(func(raw []byte) { raw[first+156] = tar.TypeDir; fixHeaderChecksum(raw[first : first+512]) }), ErrInvalidContainer},
		{"PAX header", mutate(func(raw []byte) { raw[first+156] = tar.TypeXHeader; fixHeaderChecksum(raw[first : first+512]) }), ErrInvalidContainer},
		{"traversal", mutate(func(raw []byte) {
			clear(raw[first : first+100])
			copy(raw[first:], "case/../outside.json")
			fixHeaderChecksum(raw[first : first+512])
		}), ErrInvalidPath},
		{"identity", sourceFixture(t, `{"case_id":"other"}`, `{"hostname":"alpha"}`), ErrSourceIdentity},
		{"broken manifest", sourceFixture(t, `{"case_id":"collection-1","files":{}}`, `{"hostname":"alpha"}`), ErrInvalidSource},
		{"missing reference", sourceFixture(t, `{"case_id":"collection-1","files":[{"path":"missing.json","size":0,"sha256":"`+emptySHA+`"}]}`, `{"hostname":"alpha"}`), ErrManifestReference},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parent := t.TempDir()
			keep := filepath.Join(parent, "outside.json")
			if err := os.WriteFile(keep, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := Extract(context.Background(), bytes.NewReader(test.data), parent, DefaultLimits())
			if result != nil || !errors.Is(err, test.want) {
				t.Fatalf("result=%+v err=%v want=%v", result, err, test.want)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || entries[0].Name() != "outside.json" {
				t.Fatalf("partial tree/extra write: %v %v", entries, err)
			}
			if content, err := os.ReadFile(keep); err != nil || string(content) != "keep" {
				t.Fatal("outside content changed")
			}
		})
	}
}

func TestExtractCreateIsExclusiveAndDoesNotFollowLinks(t *testing.T) {
	root := t.TempDir()
	file, err := createExtractedFile(root, "dir/file.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("keep")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if file, err := createExtractedFile(root, "dir/file.json"); !errors.Is(err, os.ErrExist) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("overwrote existing file: %v", err)
	}
	for _, path := range []string{"../escape", "/absolute", `C:\escape`, "CON.txt", "dir/../other", "dir/name:ads"} {
		if file, err := createExtractedFile(root, path); !errors.Is(err, ErrInvalidPath) {
			if file != nil {
				file.Close()
			}
			t.Fatalf("unsafe path %q: %v", path, err)
		}
	}
	out := t.TempDir()
	if err := os.Symlink(out, filepath.Join(root, "link")); err != nil {
		t.Skip(err)
	}
	if file, err := createExtractedFile(root, "link/file.json"); !errors.Is(err, ErrInvalidPath) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("followed directory link: %v", err)
	}
	if err := os.Symlink(filepath.Join(out, "absent.json"), filepath.Join(root, "leaf.json")); err != nil {
		t.Fatal(err)
	}
	if file, err := createExtractedFile(root, "leaf.json"); !errors.Is(err, os.ErrExist) {
		if file != nil {
			file.Close()
		}
		t.Fatalf("followed leaf link: %v", err)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 0 {
		t.Fatalf("writes outside extraction root: %v %v", entries, err)
	}
}

type extractionCancelReader struct {
	io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *extractionCancelReader) Read(data []byte) (int, error) {
	count, err := r.Reader.Read(data)
	r.reads++
	if r.reads == 5 {
		r.cancel()
	}
	return count, err
}

func TestExtractCancellationIOAndBudgets(t *testing.T) {
	data := sourceFixture(t, `{"case_id":"collection-1"}`, `{"hostname":"alpha"}`)
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	reader := &extractionCancelReader{Reader: bytes.NewReader(data), cancel: cancel}
	result, err := Extract(ctx, reader, parent, DefaultLimits())
	if result != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %+v %v", result, err)
	}
	failure := errors.New("input failure")
	if result, err := Extract(context.Background(), &lastErrorReader{data: data, failure: failure}, parent, DefaultLimits()); result != nil || !errors.Is(err, failure) {
		t.Fatalf("last-block IO failure: %+v %v", result, err)
	}
	limits := DefaultLimits()
	limits.ContainerBytes = int64(len(data) - 1)
	if result, err := Extract(context.Background(), bytes.NewReader(data), parent, limits); result != nil || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("container budget: %+v %v", result, err)
	}
	limits = DefaultLimits()
	limits.MetadataBytes = 700
	large := sourceFixture(t, `{"case_id":"collection-1","extra":"`+string(bytes.Repeat([]byte("x"), 701))+`"}`, `{"hostname":"alpha"}`)
	if result, err := Extract(context.Background(), bytes.NewReader(large), parent, limits); result != nil || !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("source JSON budget: %+v %v", result, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed extraction retained data: %v %v", entries, err)
	}
}

func TestExtractionCleanupRefusesReplacement(t *testing.T) {
	parent := t.TempDir()
	data := sourceFixture(t, `{"case_id":"collection-1"}`, `{"hostname":"alpha"}`)
	extracted, err := Extract(context.Background(), bytes.NewReader(data), parent, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	original := extracted.root
	saved := original + "-saved"
	if err := os.Rename(original, saved); err != nil {
		t.Fatal(err)
	}
	defer func() { os.RemoveAll(original); os.Rename(saved, original); extracted.Close() }()
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(original, "keep.json")
	if err := os.WriteFile(keep, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := extracted.Close(); err == nil {
		t.Fatal("removed replaced extraction root")
	}
	if bytes, err := os.ReadFile(keep); err != nil || string(bytes) != "replacement" {
		t.Fatal("replacement root deleted")
	}
}

func TestExtractArgumentsAndUniqueRoots(t *testing.T) {
	parent := t.TempDir()
	data := sourceFixture(t, `{"case_id":"collection-1"}`, `{"hostname":"alpha"}`)
	for _, test := range []struct {
		ctx    context.Context
		reader io.Reader
		parent string
		limits Limits
	}{
		{nil, bytes.NewReader(data), parent, DefaultLimits()},
		{context.Background(), nil, parent, DefaultLimits()},
		{context.Background(), bytes.NewReader(data), "", DefaultLimits()},
		{context.Background(), bytes.NewReader(data), filepath.Join(parent, "missing"), DefaultLimits()},
		{context.Background(), bytes.NewReader(data), parent, Limits{}},
	} {
		if result, err := Extract(test.ctx, test.reader, test.parent, test.limits); result != nil || err == nil {
			t.Fatal("invalid extraction args accepted")
		}
	}
	first, err := Extract(context.Background(), bytes.NewReader(data), parent, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Extract(context.Background(), bytes.NewReader(data), parent, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if first.CaseDir() == second.CaseDir() {
		t.Fatal("reused extraction root")
	}
}

type closingCapture struct {
	bytes.Buffer
	closed  *int
	failure error
}

func (w *closingCapture) Close() error { *w.closed++; return w.failure }

func TestContainerClosesEachCaptureBeforeNext(t *testing.T) {
	entries := []containerEntry{{"case/host/host.json", []byte(`{"hostname":"alpha"}`)}, {"case/manifest.json", []byte(`{"case_id":"collection-1"}`)}}
	for index := 0; index < 128; index++ {
		entries = append(entries, containerEntry{fmt.Sprintf("case/z/%03d.json", index), nil})
	}
	_, data, _ := containerFixture(t, entries)
	closed, opened := 0, 0
	_, err := verifySource(context.Background(), bytes.NewReader(data), DefaultLimits(), func(File) (io.Writer, error) {
		if closed != opened {
			t.Fatal("file handle held across payload boundary")
		}
		opened++
		return &closingCapture{closed: &closed}, nil
	})
	if err != nil || closed != len(entries) {
		t.Fatalf("close lifecycle: %d %v", closed, err)
	}
	failure := errors.New("close failure")
	_, err = verifySource(context.Background(), bytes.NewReader(data), DefaultLimits(), func(File) (io.Writer, error) { return &closingCapture{closed: &closed, failure: failure}, nil })
	if !errors.Is(err, failure) {
		t.Fatalf("close failure ignored: %v", err)
	}
}

func FuzzExtract(f *testing.F) {
	f.Add(sourceFixture(f, `{"case_id":"collection-1"}`, `{"hostname":"alpha"}`))
	f.Add([]byte("invalid"))
	parent := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64<<10 {
			t.Skip()
		}
		extracted, err := Extract(context.Background(), bytes.NewReader(data), parent, DefaultLimits())
		if err != nil {
			if extracted != nil {
				t.Fatal("partial extraction result")
			}
			return
		}
		if err := extracted.Close(); err != nil {
			t.Fatal(err)
		}
	})
}
