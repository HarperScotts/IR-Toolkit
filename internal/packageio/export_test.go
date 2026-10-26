package packageio

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func exportFixture(t testing.TB) (string, map[string][]byte) {
	t.Helper()
	root := t.TempDir()
	evidence := []byte("{\"path\":\"C:\\\\用户\\\\evidence\",\"pid\":17}\r\n")
	hash := sha256.Sum256(evidence)
	references, err := json.Marshal([]File{{Path: "raw/evidence.json", Size: int64(len(evidence)), SHA256: hex.EncodeToString(hash[:])}})
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{
		"host/host.json":         []byte(`{"hostname":" alpha ","platform":"windows"}`),
		"manifest.json":          []byte(`{"case_id":" collection-1 ","hostname":"fallback","files":` + string(references) + `}`),
		"raw/evidence.json":      evidence,
		"analysis/ioc.json":      []byte(`[{"id":"ioc-match:0"},{"id":"ioc-match:1"}]`),
		"analysis/network.json":  []byte(`[{"id":"network:17:TCP:127.0.0.1:1:8.8.8.8:53:ESTABLISHED","current_process":false}]`),
		"analysis/timeline.json": []byte(`[{"time":"0001-01-01T00:00:00Z","historical_process_id":"event:9"}]`),
		"a/bytes.bin":            bytes.Repeat([]byte{255}, 513),
		"a.json":                 nil,
	}
	for name, data := range contents {
		writeExportFixture(t, root, name, data)
	}
	if err := os.Mkdir(filepath.Join(root, "empty"), 0700); err != nil {
		t.Fatal(err)
	}
	return root, contents
}

func writeExportFixture(t testing.TB, root, path string, data []byte) {
	t.Helper()
	name := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestExportCaseRoundTrip(t *testing.T) {
	root, original := exportFixture(t)
	var output bytes.Buffer
	result, err := ExportCase(context.Background(), root, "display case", &output, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySource(context.Background(), bytes.NewReader(output.Bytes()), DefaultLimits())
	if err != nil || !reflect.DeepEqual(result, verified) {
		t.Fatalf("round trip: %+v %v", verified, err)
	}
	if result.Metadata.HostID != "alpha" || result.Metadata.Version != "collection-1" || result.Metadata.CaseName != "display case" || len(result.Metadata.Files) != len(original) {
		t.Fatalf("metadata: %+v", result.Metadata)
	}
	reader := tar.NewReader(bytes.NewReader(output.Bytes()))
	if header, err := reader.Next(); err != nil || header.Name != "package.json" {
		t.Fatalf("descriptor: %v, %v", header, err)
	}
	for _, file := range result.Metadata.Files {
		header, err := reader.Next()
		if err != nil || header.Name != "case/"+file.Path || header.Typeflag != tar.TypeReg || header.Format != tar.FormatUSTAR {
			t.Fatalf("header: %v %v", header, err)
		}
		actual, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(actual, original[file.Path]) {
			t.Fatalf("payload changed: %q, %v", file.Path, err)
		}
		stillOriginal, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil || !bytes.Equal(stillOriginal, original[file.Path]) {
			t.Fatalf("source changed: %q, %v", file.Path, err)
		}
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatalf("extra entry: %v", err)
	}
	// Fixed headers and unchanged bytes make repeat export byte-for-byte stable;
	// display-name changes affect the fingerprint, not source identity or bytes.
	var repeated bytes.Buffer
	if _, err := ExportCase(context.Background(), root, "display case", &repeated, DefaultLimits()); err != nil || !bytes.Equal(output.Bytes(), repeated.Bytes()) {
		t.Fatalf("deterministic export: %v", err)
	}
	var renamed bytes.Buffer
	other, err := ExportCase(context.Background(), root, "other display", &renamed, DefaultLimits())
	if err != nil || other.Metadata.ContentDigest == result.Metadata.ContentDigest || other.Metadata.HostID != result.Metadata.HostID {
		t.Fatalf("display-only name: %+v %v", other, err)
	}
}

func TestExportCasePreflightFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, string)
		want   error
	}{
		{"missing host", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "host/host.json")); err != nil {
				t.Fatal(err)
			}
		}, ErrInvalidSource},
		{"bad manifest", func(t *testing.T, root string) {
			writeExportFixture(t, root, "manifest.json", []byte(`{"case_id":"collection-1","files":{}}`))
		}, ErrInvalidSource},
		{"broken reference", func(t *testing.T, root string) { writeExportFixture(t, root, "raw/evidence.json", []byte("changed")) }, ErrManifestReference},
		{"invalid identity", func(t *testing.T, root string) {
			writeExportFixture(t, root, "host/host.json", []byte(`{"hostname":""}`))
			writeExportFixture(t, root, "manifest.json", []byte(`{"case_id":"collection-1"}`))
		}, ErrInvalidMetadata},
		{"unsafe filename", func(t *testing.T, root string) { writeExportFixture(t, root, "CON.json", nil) }, ErrInvalidPath},
		{"unicode filename", func(t *testing.T, root string) { writeExportFixture(t, root, "用户.json", nil) }, ErrInvalidPath},
		{"symlink", func(t *testing.T, root string) {
			if err := os.Symlink(filepath.Join(root, "raw/evidence.json"), filepath.Join(root, "linked.json")); err != nil {
				t.Skip(err)
			}
		}, ErrInvalidSource},
		{"directory symlink", func(t *testing.T, root string) {
			if err := os.Symlink(filepath.Join(root, "raw"), filepath.Join(root, "linked")); err != nil {
				t.Skip(err)
			}
		}, ErrInvalidSource},
		{"hard link", func(t *testing.T, root string) {
			if err := os.Link(filepath.Join(root, "raw/evidence.json"), filepath.Join(root, "linked.json")); err != nil {
				t.Skip(err)
			}
		}, ErrInvalidSource},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, _ := exportFixture(t)
			test.change(t, root)
			var output bytes.Buffer
			result, err := ExportCase(context.Background(), root, "case", &output, DefaultLimits())
			if !errors.Is(err, test.want) || output.Len() != 0 || result.ContainerBytes != 0 {
				t.Fatalf("preflight: %+v %v bytes=%d", result, err, output.Len())
			}
		})
	}
}

func TestExportCaseLimits(t *testing.T) {
	root, _ := exportFixture(t)
	var output bytes.Buffer
	result, err := ExportCase(context.Background(), root, "case", &output, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		limits   Limits
		succeeds bool
	}{
		{"exact container", DefaultLimits(), true},
		{"short container", DefaultLimits(), false},
		{"file count", DefaultLimits(), false},
		{"file bytes", DefaultLimits(), false},
		{"payload bytes", DefaultLimits(), false},
		{"source JSON", DefaultLimits(), false},
		{"descriptor", DefaultLimits(), false},
		{"invalid limits", Limits{}, false},
	}
	tests[0].limits.ContainerBytes = result.ContainerBytes
	tests[1].limits.ContainerBytes = result.ContainerBytes - 1
	tests[2].limits.FileCount = len(result.Metadata.Files) - 1
	tests[3].limits.FileBytes = 512
	tests[4].limits.PayloadBytes = result.PayloadBytes - 1
	tests[5].limits.MetadataBytes = 32
	tests[6].limits.MetadataBytes = 512 // Source JSON fits, full descriptor does not.
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			_, err := ExportCase(context.Background(), root, "case", &output, test.limits)
			if test.succeeds {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrLimitExceeded) || output.Len() != 0 {
				t.Fatalf("budget: %v bytes=%d", err, output.Len())
			}
		})
	}
}

type exportHookWriter struct {
	output bytes.Buffer
	hook   func()
	fail   error
	short  bool
}

func (w *exportHookWriter) Write(data []byte) (int, error) {
	if w.hook != nil {
		hook := w.hook
		w.hook = nil
		hook()
	}
	if w.fail != nil {
		return 0, w.fail
	}
	if w.short {
		return len(data) - 1, nil
	}
	return w.output.Write(data)
}

func TestExportCaseMutationAndIO(t *testing.T) {
	for _, kind := range []string{"same-size edit", "preserved-mtime edit", "add file", "remove file", "replace file", "writer error", "short write", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			root, _ := exportFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("output failure")
			writer := &exportHookWriter{}
			want := error(ErrSourceChanged)
			switch kind {
			case "same-size edit":
				writer.hook = func() { writeExportFixture(t, root, "a/bytes.bin", bytes.Repeat([]byte("x"), 513)) }
			case "preserved-mtime edit":
				writer.hook = func() {
					path := filepath.Join(root, "a/bytes.bin")
					info, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					writeExportFixture(t, root, "a/bytes.bin", bytes.Repeat([]byte("x"), 513))
					if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
						t.Fatal(err)
					}
				}
			case "add file":
				writer.hook = func() { writeExportFixture(t, root, "added.json", nil) }
			case "remove file":
				writer.hook = func() {
					if err := os.Remove(filepath.Join(root, "a.json")); err != nil {
						t.Fatal(err)
					}
				}
				want = os.ErrNotExist
			case "replace file":
				writer.hook = func() {
					if err := os.Remove(filepath.Join(root, "a/bytes.bin")); err != nil {
						t.Fatal(err)
					}
					writeExportFixture(t, root, "a/bytes.bin", bytes.Repeat([]byte{255}, 513))
				}
			case "writer error":
				writer.fail = failure
				want = failure
			case "short write":
				writer.short = true
				want = io.ErrShortWrite
			case "cancel":
				writer.hook = cancel
				want = context.Canceled
			}
			result, err := ExportCase(ctx, root, "case", writer, DefaultLimits())
			if !errors.Is(err, want) || result.Metadata.Format != "" || result.ContainerBytes != 0 {
				t.Fatalf("failure: %+v %v want %v", result, err, want)
			}
		})
	}
}

func TestExportCaseDirectoryAlias(t *testing.T) {
	root, _ := exportFixture(t)
	if err := os.Mkdir(filepath.Join(root, "A"), 0700); err != nil {
		t.Skip("filesystem does not support distinct case-only directory names")
	}
	var output bytes.Buffer
	if _, err := ExportCase(context.Background(), root, "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidPath) || output.Len() != 0 {
		t.Fatalf("directory alias: %v", err)
	}
}

func TestExportCaseArgumentsAndRoot(t *testing.T) {
	root, _ := exportFixture(t)
	var output bytes.Buffer
	if _, err := ExportCase(nil, root, "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatal(err)
	}
	if _, err := ExportCase(context.Background(), root, "case", nil, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatal(err)
	}
	if _, err := ExportCase(context.Background(), "", "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatal(err)
	}
	if _, err := ExportCase(context.Background(), root, " case ", &output, DefaultLimits()); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatal(err)
	}
	if _, err := ExportCase(context.Background(), filepath.Join(root, "manifest.json"), "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "case-link")
	if err := os.Symlink(root, link); err != nil {
		t.Skip(err)
	}
	if _, err := ExportCase(context.Background(), link, "case", &output, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExportCase(ctx, root, "case", &output, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if output.Len() != 0 {
		t.Fatal("invalid arguments wrote output")
	}
}
