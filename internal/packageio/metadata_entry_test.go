package packageio

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"unicode/utf8"
)

// Keep the old per-entry decoder as a test-only compatibility oracle.
func readFileEntryReference(data []byte) (File, error) {
	object, err := readObject(data, []string{"path", "size", "sha256"})
	if err != nil {
		return File{}, err
	}
	var file File
	for _, field := range []struct {
		key    string
		target any
	}{{"path", &file.Path}, {"size", &file.Size}, {"sha256", &file.SHA256}} {
		if err := json.Unmarshal(object[field.key], field.target); err != nil {
			return File{}, err
		}
	}
	return file, nil
}

func compareFileEntry(t *testing.T, data []byte) {
	t.Helper()
	// Both entry readers run after the whole descriptor's Unicode checks.
	if !utf8.Valid(data) || !validJSONEscapes(data) {
		return
	}
	want, oldErr := readFileEntryReference(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	got, err := readFileEntry(decoder)
	if err == nil && decoder.Decode(new(any)) != io.EOF {
		err = ErrInvalidMetadata
	}
	if (err == nil) != (oldErr == nil) || (err == nil && got != want) {
		t.Fatalf("entry compatibility: data=%q new=%+v/%v old=%+v/%v", data, got, err, want, oldErr)
	}
}

func fileEntrySeeds() []string {
	return []string{
		`{"path":"manifest.json","size":0,"sha256":"hash"}`,
		`{"sha256":"hash","size":-0,"p\u0061th":"a😀"}`,
		`{"path":"a","size":9223372036854775807,"sha256":"h"}`,
		`{"path":"a","size":-9223372036854775808,"sha256":"h"}`,
		`{"path":"a","size":9223372036854775808,"sha256":"h"}`,
		`{"path":"a","size":-9223372036854775809,"sha256":"h"}`,
		`{"path":"a","size":0e0,"sha256":"h"}`,
		`{"path":"a","size":0.0,"sha256":"h"}`,
		`{"path":"a","size":"0","sha256":"h"}`,
		`{"path":"a","size":null,"sha256":"h"}`,
		`{"path":null,"size":0,"sha256":"h"}`,
		`{"path":"a","size":0,"sha256":null}`,
		`{"path":"a","size":0,"sha256":[]}`,
		`{"path":"a","size":{},"sha256":"h"}`,
		`{"path":"a","size":0,"sha256":"h","p\u0061th":"b"}`,
		`{"Path":"a","size":0,"sha256":"h"}`,
		`{"path":"a","size":0,"sha256":"h","extra":true}`,
		`{"path":"a","sha256":"h"}`,
		`{"path":"a","size":0,"sha256":"h"} {}`,
		`{"path":"\ud83d\ude00","size":0,"sha256":"h"}`,
		`{"path":"\ud800","size":0,"sha256":"h"}`,
		`[]`, `null`, `{}`, `{"path":`,
	}
}

func TestFileEntryCompatibility(t *testing.T) {
	for _, seed := range fileEntrySeeds() {
		compareFileEntry(t, []byte(seed))
	}
}

func FuzzFileEntryCompatibility(f *testing.F) {
	for _, seed := range fileEntrySeeds() {
		f.Add([]byte(seed))
	}
	f.Fuzz(compareFileEntry)
}

func BenchmarkFileEntryDecoders(b *testing.B) {
	data := []byte(fileEntrySeeds()[0])
	for _, shared := range []bool{false, true} {
		name := "per-entry-reference"
		if shared {
			name = "shared-array"
		}
		b.Run(name, func(b *testing.B) {
			const count = 256
			array := append([]byte{'['}, bytes.Repeat(append(append([]byte{}, data...), ','), count)...)
			array[len(array)-1] = ']'
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				decoder := json.NewDecoder(bytes.NewReader(array))
				decoder.UseNumber()
				if _, err := decoder.Token(); err != nil {
					b.Fatal(err)
				}
				for decoder.More() {
					var err error
					if shared {
						_, err = readFileEntry(decoder)
					} else {
						var raw json.RawMessage
						err = decoder.Decode(&raw)
						if err == nil {
							_, err = readFileEntryReference(raw)
						}
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				if _, err := decoder.Token(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
