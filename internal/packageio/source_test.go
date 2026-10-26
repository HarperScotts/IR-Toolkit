package packageio

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func sourceFixture(t testing.TB, manifest, host string) []byte {
	t.Helper()
	_, data, _ := containerFixture(t, []containerEntry{
		{name: "case/host/host.json", data: []byte(host)},
		{name: "case/manifest.json", data: []byte(manifest)},
		{name: "case/raw/evidence.json", data: []byte("evidence")},
	})
	return data
}

func TestVerifySource(t *testing.T) {
	hash := sha256.Sum256([]byte("evidence"))
	refs, _ := json.Marshal([]File{{Path: "raw/evidence.json", Size: 8, SHA256: hex.EncodeToString(hash[:])}})
	tests := []struct {
		name, manifest, host string
		want                 error
	}{
		{"subset", `{"case_id":"collection-1","hostname":"other","files":` + string(refs) + `}`, `{"hostname":"alpha","extra":{"nested":true}}`, nil},
		{"trimmed", `{"case_id":" collection-1 ","files":[]}`, `{"hostname":" alpha "}`, nil},
		{"fallback", `{"case_id":"collection-1","hostname":"alpha","files":null}`, `{"hostname":" "}`, nil},
		{"absent hostname", `{"case_id":"collection-1","hostname":"alpha"}`, `{}`, nil},
		{"host mismatch", `{"case_id":"collection-1","hostname":"alpha"}`, `{"hostname":"beta"}`, ErrSourceIdentity},
		{"version mismatch", `{"case_id":"other"}`, `{"hostname":"alpha"}`, ErrSourceIdentity},
		{"missing version", `{}`, `{"hostname":"alpha"}`, ErrInvalidSource},
		{"null host", `{"case_id":"collection-1"}`, `{"hostname":null}`, ErrInvalidSource},
		{"number version", `{"case_id":1}`, `{"hostname":"alpha"}`, ErrInvalidSource},
		{"duplicate", `{"case_id":"collection-1"}`, `{"hostname":"alpha","host\u006eame":"alpha"}`, ErrInvalidSource},
		{"alias", `{"case_id":"collection-1"}`, `{"HOSTNAME":"alpha"}`, ErrInvalidSource},
		{"unicode alias", `{"case_id":"collection-1"}`, `{"hostname":"alpha","xS":1,"xſ":2}`, ErrInvalidSource},
		{"trailing", `{"case_id":"collection-1"}`, `{"hostname":"alpha"}{}`, ErrInvalidSource},
		{"surrogate", `{"case_id":"collection-1"}`, `{"hostname":"alpha","extra":"\ud800"}`, ErrInvalidSource},
		{"invalid unicode", `{"case_id":"collection-1"}`, "{\"hostname\":\"alpha\",\"extra\":\"\xff\"}", ErrInvalidSource},
		{"files object", `{"case_id":"collection-1","files":{}}`, `{"hostname":"alpha"}`, ErrInvalidSource},
		{"missing reference", `{"case_id":"collection-1","files":[{"path":"missing.json","size":0,"sha256":"` + emptySHA + `"}]}`, `{"hostname":"alpha"}`, ErrManifestReference},
		{"wrong size", `{"case_id":"collection-1","files":[{"path":"raw/evidence.json","size":0,"sha256":"` + emptySHA + `"}]}`, `{"hostname":"alpha"}`, ErrManifestReference},
		{"wrong hash", `{"case_id":"collection-1","files":[{"path":"raw/evidence.json","size":8,"sha256":"` + emptySHA + `"}]}`, `{"hostname":"alpha"}`, ErrManifestReference},
		{"unsafe path", `{"case_id":"collection-1","files":[{"path":"../x","size":0,"sha256":"` + emptySHA + `"}]}`, `{"hostname":"alpha"}`, ErrInvalidPath},
		{"float size", `{"case_id":"collection-1","files":[{"path":"raw/evidence.json","size":8.0,"sha256":"` + emptySHA + `"}]}`, `{"hostname":"alpha"}`, ErrInvalidSource},
		{"duplicate reference", `{"case_id":"collection-1","files":[` + string(refs[1:len(refs)-1]) + `,` + string(refs[1:len(refs)-1]) + `]}`, `{"hostname":"alpha"}`, ErrManifestReference},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := sourceFixture(t, test.manifest, test.host)
			if _, err := VerifyContainer(context.Background(), bytes.NewReader(data), DefaultLimits()); err != nil {
				t.Fatalf("self-consistent container: %v", err)
			}
			result, err := VerifySource(context.Background(), bytes.NewReader(data), DefaultLimits())
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
			if err != nil && (result.Metadata.Format != "" || result.ContainerBytes != 0) {
				t.Fatal("partial result on failure")
			}
		})
	}
}

func TestVerifySourceBoundaries(t *testing.T) {
	data := sourceFixture(t, `{"case_id":"collection-1"}`, `{"hostname":"alpha"}`)
	_, err := VerifySource(context.Background(), bytes.NewReader(append(data, 1)), DefaultLimits())
	if !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("invalid tail: %v", err)
	}
	_, missing, _ := containerFixture(t, []containerEntry{{name: "case/manifest.json", data: []byte(`{"case_id":"collection-1","hostname":"alpha"}`)}})
	if _, err := VerifySource(context.Background(), bytes.NewReader(missing), DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("missing host: %v", err)
	}
	limits := DefaultLimits()
	limits.MetadataBytes = 2048
	largeHost := `{"hostname":"alpha","extra":"` + string(bytes.Repeat([]byte("x"), 2048)) + `"}`
	if _, err := VerifySource(context.Background(), bytes.NewReader(sourceFixture(t, `{"case_id":"collection-1"}`, largeHost)), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("source budget: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifySource(ctx, bytes.NewReader(data), DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
}

func FuzzVerifySource(f *testing.F) {
	f.Add(sourceFixture(f, `{"case_id":"collection-1","files":null}`, `{"hostname":"alpha"}`))
	f.Add([]byte("invalid"))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := VerifySource(context.Background(), bytes.NewReader(data), DefaultLimits())
		if err != nil && result.ContainerBytes != 0 {
			t.Fatal("partial result")
		}
	})
}

// Rebuild the descriptor/hash for each mutation so fuzzing reaches the source
// parser rather than stopping at the outer container integrity check.
func FuzzVerifySourceJSON(f *testing.F) {
	f.Add(`{"case_id":"collection-1","files":null}`, `{"hostname":"alpha"}`)
	f.Add(`{"case_id":"collection-1","files":[]}`, `{"hostname":"alpha","HOSTNAME":"beta"}`)
	f.Fuzz(func(t *testing.T, manifest, host string) {
		if len(manifest) > 4096 || len(host) > 4096 {
			t.Skip()
		}
		data := sourceFixture(t, manifest, host)
		result, err := VerifySource(context.Background(), bytes.NewReader(data), DefaultLimits())
		if err != nil && result.ContainerBytes != 0 {
			t.Fatal("partial result")
		}
	})
}
