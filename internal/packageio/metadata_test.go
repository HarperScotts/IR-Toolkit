package packageio

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const goldenDigest = "d3bc5ffad1fcb9a77ab2c57df319ebf902c874e5e41470933486c70fd409d066"

func fixtureMetadata() Metadata {
	return Metadata{Format: Format, FormatVersion: FormatVersion, Profile: Profile,
		HostID: "alpha", Version: "collection-1", CaseName: "case-a", ContentDigest: goldenDigest,
		Files: []File{{Path: "manifest.json", Size: 0, SHA256: emptySHA}}}
}

func encodedMetadata(t *testing.T, metadata Metadata) []byte {
	t.Helper()
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestContentDigestGoldenAndRoundTrip(t *testing.T) {
	metadata := fixtureMetadata()
	// Golden independently computed with Node crypto from the contract's binary
	// encoding, not from ContentDigest or a second copy of this Go implementation.
	got, err := ContentDigest(metadata, DefaultLimits())
	if err != nil || got != goldenDigest {
		t.Fatalf("digest=%s, error=%v", got, err)
	}
	if err := ValidateMetadata(metadata, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	for _, pretty := range []bool{false, true} {
		data := encodedMetadata(t, metadata)
		if pretty {
			var output bytes.Buffer
			if err := json.Indent(&output, data, "", "  "); err != nil {
				t.Fatal(err)
			}
			data = append(output.Bytes(), '\n')
		}
		parsed, err := ReadMetadata(bytes.NewReader(data), DefaultLimits())
		if err != nil || !reflect.DeepEqual(parsed, metadata) {
			t.Fatalf("round trip: %+v, %v", parsed, err)
		}
	}
	metadata.Files[0].SHA256 = strings.Repeat("a", 64)
	changed, err := ContentDigest(metadata, DefaultLimits())
	if err != nil || changed == goldenDigest {
		t.Fatal("file hash change did not change fingerprint")
	}
	metadata.ContentDigest = changed
	if err := ValidateMetadata(metadata, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	metadata.HostID = "beta"
	changed, err = ContentDigest(metadata, DefaultLimits())
	if err != nil || changed == metadata.ContentDigest {
		t.Fatal("identity change did not change fingerprint")
	}
	nonzero := fixtureMetadata()
	nonzero.Files[0].Size = 3
	nonzero.Files[0].SHA256 = "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
	nonzero.ContentDigest = "b4ab6c3f006f8d5a6dab5d997395e63cd5f9ea5d49e080c1369582855215b0d4"
	if err := ValidateMetadata(nonzero, DefaultLimits()); err != nil {
		t.Fatalf("nonzero size golden: %v", err)
	}
}

func TestReadMetadataRejectsInvalidJSONAndFields(t *testing.T) {
	original := string(encodedMetadata(t, fixtureMetadata()))
	replace := func(old, new string) string { return strings.Replace(original, old, new, 1) }
	tests := map[string]string{
		"empty":                 "",
		"array":                 "[]",
		"null":                  "null",
		"duplicate":             replace(`"host_id":"alpha"`, `"host_id":"alpha","host_id":"beta"`),
		"escaped duplicate":     replace(`"host_id":"alpha"`, `"host_id":"alpha","host\u005fid":"beta"`),
		"case folded field":     replace(`"host_id"`, `"HOST_ID"`),
		"unknown":               replace(`"host_id":"alpha"`, `"host_id":"alpha","destination":"/tmp/other"`),
		"missing":               replace(`"host_id":"alpha",`, ""),
		"null field":            replace(`"host_id":"alpha"`, `"host_id":null`),
		"null files":            replace(`"files":[{"path":"manifest.json","size":0,"sha256":"`+emptySHA+`"}]`, `"files":null`),
		"empty files":           replace(`"files":[{"path":"manifest.json","size":0,"sha256":"`+emptySHA+`"}]`, `"files":[]`),
		"null entry":            replace(`{"path":"manifest.json","size":0,"sha256":"`+emptySHA+`"}`, "null"),
		"unknown entry":         replace(`"path":"manifest.json"`, `"path":"manifest.json","mode":777`),
		"duplicate entry field": replace(`"size":0`, `"size":0,"size":1`),
		"missing size":          replace(`"size":0,`, ""),
		"null size":             replace(`"size":0`, `"size":null`),
		"negative":              replace(`"size":0`, `"size":-1`),
		"float":                 replace(`"size":0`, `"size":0.0`),
		"exponent":              replace(`"size":0`, `"size":0e0`),
		"string size":           replace(`"size":0`, `"size":"0"`),
		"overflow":              replace(`"size":0`, `"size":9223372036854775808`),
		"bad version":           replace(`"format_version":1`, `"format_version":2`),
		"float version":         replace(`"format_version":1`, `"format_version":1.0`),
		"bad profile":           replace(Profile, "raw-only"),
		"bad format":            replace(Format, "other-format"),
		"trailing object":       original + "{}",
		"trailing garbage":      original + "garbage",
		"truncated":             original[:len(original)-1],
		"unpaired high":         replace(`"host_id":"alpha"`, `"host_id":"\ud800"`),
		"unpaired low":          replace(`"host_id":"alpha"`, `"host_id":"\udc00"`),
		"wrong low":             replace(`"host_id":"alpha"`, `"host_id":"\ud800\u0041"`),
		"invalid utf8":          replace("alpha", string([]byte{0xff})),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			metadata, err := ReadMetadata(strings.NewReader(raw), DefaultLimits())
			if !errors.Is(err, ErrInvalidMetadata) || !reflect.DeepEqual(metadata, Metadata{}) {
				t.Fatalf("accepted or wrong error: %+v, %v", metadata, err)
			}
		})
	}
}

func TestMetadataUnicodeEscapesRemainExact(t *testing.T) {
	for _, identity := range []string{"host-😀", `host-�`, `host-A`, `host-"\"quoted`} {
		metadata := fixtureMetadata()
		metadata.HostID = identity
		digest, err := ContentDigest(metadata, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		metadata.ContentDigest = digest
		raw := encodedMetadata(t, metadata)
		if identity == "host-😀" {
			raw = bytes.ReplaceAll(raw, []byte("😀"), []byte(`\ud83d\ude00`))
		}
		if identity == "host-�" {
			raw = bytes.ReplaceAll(raw, []byte("�"), []byte(`\ufffd`))
		}
		if identity == "host-A" {
			raw = bytes.ReplaceAll(raw, []byte("host-A"), []byte(`host-\u0041`))
		}
		got, err := ReadMetadata(bytes.NewReader(raw), DefaultLimits())
		if err != nil || !reflect.DeepEqual(got, metadata) {
			t.Fatalf("Unicode/escapes changed: %+v, %v", got, err)
		}
	}
}

func TestValidateMetadataRejectsIdentityAndInventory(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Metadata)
		want   error
	}{
		{"empty host", func(m *Metadata) { m.HostID = "" }, ErrInvalidMetadata},
		{"trim host", func(m *Metadata) { m.HostID = " alpha" }, ErrInvalidMetadata},
		{"invalid host utf8", func(m *Metadata) { m.HostID = string([]byte{255}) }, ErrInvalidMetadata},
		{"control name", func(m *Metadata) { m.CaseName = "a\n" }, ErrInvalidMetadata},
		{"empty name", func(m *Metadata) { m.CaseName = "" }, ErrInvalidMetadata},
		{"long version", func(m *Metadata) { m.Version = strings.Repeat("a", 257) }, ErrInvalidMetadata},
		{"uppercase hash", func(m *Metadata) { m.Files[0].SHA256 = strings.ToUpper(emptySHA) }, ErrInvalidMetadata},
		{"bad digest", func(m *Metadata) { m.ContentDigest = "not-hex" }, ErrInvalidMetadata},
		{"mismatch", func(m *Metadata) { m.ContentDigest = strings.Repeat("0", 64) }, ErrDigestMismatch},
		{"manifest missing", func(m *Metadata) { m.Files[0].Path = "other.json" }, ErrInvalidMetadata},
		{"duplicate", func(m *Metadata) { m.Files = append(m.Files, m.Files[0]) }, ErrInvalidMetadata},
		{"unsorted", func(m *Metadata) { m.Files = append(m.Files, File{Path: "a.json", SHA256: emptySHA}) }, ErrInvalidMetadata},
		{"file alias", func(m *Metadata) { m.Files = []File{{Path: "Manifest.json", SHA256: emptySHA}, m.Files[0]} }, ErrInvalidPath},
		{"directory alias", func(m *Metadata) {
			m.Files = []File{{Path: "A/x", SHA256: emptySHA}, {Path: "a/y", SHA256: emptySHA}, m.Files[0]}
		}, ErrInvalidPath},
		{"file directory conflict", func(m *Metadata) {
			m.Files = []File{{Path: "a", SHA256: emptySHA}, {Path: "a/b", SHA256: emptySHA}, m.Files[0]}
		}, ErrInvalidPath},
		{"path traversal", func(m *Metadata) { m.Files[0].Path = "../manifest.json" }, ErrInvalidPath},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := fixtureMetadata()
			test.change(&metadata)
			before := encodedMetadata(t, metadata)
			if err := ValidateMetadata(metadata, DefaultLimits()); !errors.Is(err, test.want) {
				t.Fatalf("error=%v, want %v", err, test.want)
			}
			if !bytes.Equal(before, encodedMetadata(t, metadata)) {
				t.Fatal("validator silently rewrote metadata")
			}
		})
	}
}

func TestMetadataLimitsAndIntegerBoundaries(t *testing.T) {
	metadata := fixtureMetadata()
	limits := DefaultLimits()
	raw := encodedMetadata(t, metadata)
	limits.MetadataBytes = int64(len(raw))
	if _, err := ReadMetadata(bytes.NewReader(raw), limits); err != nil {
		t.Fatal(err)
	}
	limits.MetadataBytes--
	reader := &countingReader{Reader: bytes.NewReader(append(raw, bytes.Repeat([]byte(" "), 4096)...))}
	if _, err := ReadMetadata(reader, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("byte limit: %v", err)
	}
	if reader.count != limits.MetadataBytes+1 {
		t.Fatalf("read beyond bounded descriptor: %d", reader.count)
	}
	limits = DefaultLimits()
	limits.FileCount = 1
	metadata.Files = append(metadata.Files, File{Path: "process/processes.json", SHA256: emptySHA})
	if _, err := ReadMetadata(bytes.NewReader(encodedMetadata(t, metadata)), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("file count: %v", err)
	}
	metadata = fixtureMetadata()
	metadata.Files[0].Size = DefaultLimits().FileBytes
	if _, err := ContentDigest(metadata, DefaultLimits()); err != nil {
		t.Fatalf("exact file limit: %v", err)
	}
	metadata.Files[0].Size++
	if _, err := ContentDigest(metadata, DefaultLimits()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("file limit: %v", err)
	}
	metadata.Files[0].Size = 1<<63 - 1
	if _, err := ContentDigest(metadata, DefaultLimits()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("large integer: %v", err)
	}
	metadata = fixtureMetadata()
	metadata.Files = []File{{Path: "a", Size: 1, SHA256: emptySHA}, {Path: "manifest.json", Size: 1, SHA256: emptySHA}}
	limits = DefaultLimits()
	limits.PayloadBytes = 2
	if _, err := ContentDigest(metadata, limits); err != nil {
		t.Fatalf("exact total limit: %v", err)
	}
	limits.PayloadBytes = 1
	if _, err := ContentDigest(metadata, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("total limit: %v", err)
	}
	metadata = fixtureMetadata()
	metadata.Files = []File{
		{Path: "a", Size: 64 << 20, SHA256: emptySHA},
		{Path: "b", Size: 64 << 20, SHA256: emptySHA},
		{Path: "c", Size: 64 << 20, SHA256: emptySHA},
		{Path: "manifest.json", Size: 64 << 20, SHA256: emptySHA},
	}
	if _, err := ContentDigest(metadata, DefaultLimits()); err != nil {
		t.Fatalf("exact default total limit: %v", err)
	}
	metadata.Files = append(metadata.Files, File{Path: "n", Size: 1, SHA256: emptySHA})
	if _, err := ContentDigest(metadata, DefaultLimits()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("default total overflow: %v", err)
	}
	for _, invalid := range []Limits{{}, {MetadataBytes: 1 << 62, FileCount: 1, FileBytes: 1, PayloadBytes: 1, ContainerBytes: 1}} {
		if _, err := ReadMetadata(bytes.NewReader(raw), invalid); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("invalid limits: %v", err)
		}
	}
}

type countingReader struct {
	io.Reader
	count int64
}

func (r *countingReader) Read(data []byte) (int, error) {
	n, err := r.Reader.Read(data)
	r.count += int64(n)
	return n, err
}

type failedReader struct{ err error }

func (r failedReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadMetadataPreservesIOErrors(t *testing.T) {
	failure := errors.New("fixture IO failure")
	if _, err := ReadMetadata(failedReader{failure}, DefaultLimits()); !errors.Is(err, failure) {
		t.Fatalf("IO error lost: %v", err)
	}
	if _, err := ReadMetadata(io.MultiReader(bytes.NewReader(encodedMetadata(t, fixtureMetadata())), failedReader{failure}), DefaultLimits()); !errors.Is(err, failure) {
		t.Fatalf("partial read error lost: %v", err)
	}
	if _, err := ReadMetadata(nil, DefaultLimits()); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("nil reader: %v", err)
	}
}

func FuzzReadMetadata(f *testing.F) {
	raw, _ := json.Marshal(fixtureMetadata())
	f.Add(raw)
	f.Add([]byte(`{"host_id":"\ud800"}`))
	f.Add([]byte(`{"files":[{"size":9223372036854775808}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadMetadata(bytes.NewReader(data), DefaultLimits())
		if err == nil {
			if err := ValidateMetadata(got, DefaultLimits()); err != nil {
				t.Fatalf("reader accepted invalid descriptor: %v", err)
			}
			roundTrip, err := ReadMetadata(bytes.NewReader(encodedMetadata(t, got)), DefaultLimits())
			if err != nil || !reflect.DeepEqual(got, roundTrip) {
				t.Fatalf("unstable descriptor: %v", err)
			}
		}
	})
}
