package packageio

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type containerEntry struct {
	name string
	data []byte
}

func containerFixture(t testing.TB, entries []containerEntry) (Metadata, []byte, int) {
	t.Helper()
	metadata := fixtureMetadata()
	metadata.Files = nil
	for _, entry := range entries {
		hash := sha256.Sum256(entry.data)
		metadata.Files = append(metadata.Files, File{Path: strings.TrimPrefix(entry.name, "case/"), Size: int64(len(entry.data)), SHA256: hex.EncodeToString(hash[:])})
	}
	digest, err := ContentDigest(metadata, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	metadata.ContentDigest = digest
	descriptor, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	data := writeContainerFixture(t, descriptor, entries)
	return metadata, data, 512 + ((len(descriptor)+511)/512)*512
}

func writeContainerFixture(t testing.TB, descriptor []byte, entries []containerEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	all := append([]containerEntry{{name: "package.json", data: descriptor}}, entries...)
	for _, entry := range all {
		if err := writer.WriteHeader(&tar.Header{Name: entry.name, Size: int64(len(entry.data)), Mode: 0600, ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func fixHeaderChecksum(header []byte) {
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	checksum := 0
	for _, value := range header[:512] {
		checksum += int(value)
	}
	copy(header[148:156], []byte(fmt.Sprintf("%06o\x00 ", checksum)))
}

func TestVerifyContainerActualBytesAndBoundaries(t *testing.T) {
	for _, body := range [][]byte{nil, []byte("{}\n"), bytes.Repeat([]byte("x"), 512), bytes.Repeat([]byte("x"), 513)} {
		metadata, data, _ := containerFixture(t, []containerEntry{{"case/manifest.json", body}})
		for _, tail := range []int{0, 512, maxTailBytes} {
			raw := append(bytes.Clone(data), make([]byte, tail)...)
			limits := DefaultLimits()
			limits.ContainerBytes = int64(len(raw))
			reader := &countingReader{Reader: bytes.NewReader(raw)}
			verified, err := VerifyContainer(context.Background(), reader, limits)
			if err != nil || !reflect.DeepEqual(verified.Metadata, metadata) || verified.PayloadBytes != int64(len(body)) || verified.ContainerBytes != int64(len(raw)) || reader.count != int64(len(raw)) {
				t.Fatalf("verification: %+v, %v", verified, err)
			}
			if _, err := VerifyContainer(context.Background(), &lastErrorReader{data: bytes.Clone(raw), failure: io.EOF}, limits); err != nil {
				t.Fatalf("valid final bytes alongside EOF: %v", err)
			}
		}
	}
}

func TestVerifyContainerRejectsTransparentGNULongName(t *testing.T) {
	metadata, _, _ := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}")}})
	descriptor, _ := json.Marshal(metadata)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	longName := "case/" + strings.Repeat("a", 101)
	for _, entry := range []struct {
		header tar.Header
		data   []byte
	}{
		{tar.Header{Name: "package.json", Size: int64(len(descriptor)), Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, descriptor},
		{tar.Header{Name: longName, Size: 2, Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatGNU}, []byte("{}")},
	} {
		if err := writer.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ordinary := tar.NewReader(bytes.NewReader(output.Bytes()))
	if _, err := ordinary.Next(); err != nil {
		t.Fatal(err)
	}
	header, err := ordinary.Next()
	if err != nil || header.Name != longName {
		t.Fatalf("fixture does not exercise transparent GNU name: %+v, %v", header, err)
	}
	if _, err := VerifyContainer(context.Background(), bytes.NewReader(output.Bytes()), DefaultLimits()); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("hidden GNU extension accepted: %v", err)
	}
}

func TestVerifyContainerDoesNotAutodetectCompression(t *testing.T) {
	_, data, _ := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}")}})
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	if _, err := gzipWriter.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var zipped bytes.Buffer
	zipWriter := zip.NewWriter(&zipped)
	entry, err := zipWriter.Create("package.ircase.tar")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{compressed.Bytes(), zipped.Bytes()} {
		if _, err := VerifyContainer(context.Background(), bytes.NewReader(raw), DefaultLimits()); !errors.Is(err, ErrInvalidContainer) {
			t.Fatalf("compressed container accepted: %v", err)
		}
	}
}

func TestVerifyContainerRejectsEveryTruncatedPrefix(t *testing.T) {
	_, data, _ := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}\n")}})
	for length := 0; length < len(data); length++ {
		got, err := VerifyContainer(context.Background(), bytes.NewReader(data[:length]), DefaultLimits())
		if err == nil || !reflect.DeepEqual(got, ContainerVerification{}) {
			t.Fatalf("truncated stream accepted at %d: %+v", length, got)
		}
	}
}

func TestVerifyContainerRejectsRawHeaderVariants(t *testing.T) {
	_, data, firstPayload := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}\n")}})
	tests := map[string]func([]byte){
		"GNU magic":       func(h []byte) { copy(h[257:265], []byte("ustar  \x00")) },
		"V7 magic":        func(h []byte) { clear(h[257:265]) },
		"unknown version": func(h []byte) { copy(h[263:265], []byte("01")) },
		"base256 size":    func(h []byte) { clear(h[124:136]); h[124] = 0x80; h[135] = 3 },
		"negative size":   func(h []byte) { clear(h[124:136]); copy(h[124:136], []byte("-0000000003")) },
		"non-octal size":  func(h []byte) { h[124] = '9' },
		"size overflow": func(h []byte) {
			for i := 124; i < 136; i++ {
				h[i] = '7'
			}
		},
		"prefix":            func(h []byte) { h[345] = 'a' },
		"link target":       func(h []byte) { h[157] = 'a' },
		"hidden name bytes": func(h []byte) { h[99] = 'a' },
		"extended tail":     func(h []byte) { h[511] = 'a' },
		"absolute path":     func(h []byte) { clear(h[:100]); copy(h[:100], []byte("/etc/passwd")) },
		"traversal":         func(h []byte) { clear(h[:100]); copy(h[:100], []byte("case/../x")) },
		"drive path":        func(h []byte) { clear(h[:100]); copy(h[:100], []byte("case/C:/x")) },
		"ADS":               func(h []byte) { clear(h[:100]); copy(h[:100], []byte("case/x:stream")) },
		"device name":       func(h []byte) { clear(h[:100]); copy(h[:100], []byte("case/NUL.json")) },
	}
	for _, flag := range []byte{tar.TypeRegA, tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo, tar.TypeCont, tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNUSparse, tar.TypeGNULongName, tar.TypeGNULongLink, 'z'} {
		tests[fmt.Sprintf("raw type %q", flag)] = func(h []byte) { h[156] = flag }
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Clone(data)
			header := raw[firstPayload : firstPayload+512]
			change(header)
			fixHeaderChecksum(header)
			reader := &countingReader{Reader: bytes.NewReader(raw)}
			result, err := VerifyContainer(context.Background(), reader, DefaultLimits())
			if err == nil || !reflect.DeepEqual(result, ContainerVerification{}) {
				t.Fatalf("header variant accepted: %+v", result)
			}
			if reader.count != int64(firstPayload+512) {
				t.Fatalf("read data behind invalid header: %d", reader.count)
			}
		})
	}
	// Invalid checksum is checked by the standard library after raw filtering.
	raw := bytes.Clone(data)
	raw[firstPayload+100] ^= 1
	if _, err := VerifyContainer(context.Background(), bytes.NewReader(raw), DefaultLimits()); !errors.Is(err, tar.ErrHeader) {
		t.Fatalf("checksum accepted: %v", err)
	}
}

func TestVerifyContainerRejectsTransparentPAXExtension(t *testing.T) {
	metadata, _, _ := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}")}})
	descriptor, _ := json.Marshal(metadata)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{Name: "package.json", Size: int64(len(descriptor)), Mode: 0600, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(descriptor); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteHeader(&tar.Header{Name: "case/manifest.json", Size: 2, Mode: 0600, Format: tar.FormatPAX, PAXRecords: map[string]string{"comment": "hidden extension"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ordinary := tar.NewReader(bytes.NewReader(output.Bytes()))
	if _, err := ordinary.Next(); err != nil {
		t.Fatal(err)
	}
	header, err := ordinary.Next()
	if err != nil || header.Name != "case/manifest.json" || header.PAXRecords["comment"] != "hidden extension" {
		t.Fatalf("fixture does not exercise transparent PAX: %+v, %v", header, err)
	}
	if _, err := VerifyContainer(context.Background(), bytes.NewReader(output.Bytes()), DefaultLimits()); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("hidden extension accepted: %v", err)
	}
}

func TestVerifyContainerRejectsInventoryAndFramingMismatch(t *testing.T) {
	metadata, data, firstPayload := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}\n")}})
	descriptor, _ := json.Marshal(metadata)
	cases := map[string][]byte{}
	corrupt := bytes.Clone(data)
	corrupt[firstPayload+512] = 'x'
	cases["body hash"] = corrupt
	corrupt = bytes.Clone(data)
	corrupt[firstPayload+512+3] = 1
	cases["payload padding"] = corrupt
	corrupt = bytes.Clone(data)
	corrupt[512+len(descriptor)] = 1
	cases["metadata padding"] = corrupt
	corrupt = bytes.Clone(data)
	clear(corrupt[firstPayload : firstPayload+100])
	copy(corrupt[firstPayload:firstPayload+100], []byte("case/other.json"))
	fixHeaderChecksum(corrupt[firstPayload : firstPayload+512])
	cases["wrong filename"] = corrupt
	corrupt = bytes.Clone(data)
	copy(corrupt[firstPayload+124:firstPayload+136], []byte("00000000004\x00"))
	fixHeaderChecksum(corrupt[firstPayload : firstPayload+512])
	cases["header size"] = corrupt
	cases["missing payload"] = writeContainerFixture(t, descriptor, nil)
	cases["extra payload"] = writeContainerFixture(t, descriptor, []containerEntry{{"case/manifest.json", []byte("{}\n")}, {"case/extra.json", []byte("extra")}})
	cases["duplicate payload"] = writeContainerFixture(t, descriptor, []containerEntry{{"case/manifest.json", []byte("{}\n")}, {"case/manifest.json", []byte("{}\n")}})
	cases["concatenated archive"] = append(bytes.Clone(data), data...)
	cases["partial trailing block"] = append(bytes.Clone(data), make([]byte, 511)...)
	cases["non-zero tail"] = append(bytes.Clone(data), bytes.Repeat([]byte("x"), 512)...)
	cases["too much zero tail"] = append(bytes.Clone(data), make([]byte, maxTailBytes+512)...)
	corrupt = bytes.Clone(data)
	clear(corrupt[:100])
	copy(corrupt[:100], []byte("case/manifest.json"))
	fixHeaderChecksum(corrupt[:512])
	cases["wrong first entry"] = corrupt
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := VerifyContainer(context.Background(), bytes.NewReader(raw), DefaultLimits())
			if err == nil || !reflect.DeepEqual(result, ContainerVerification{}) {
				t.Fatalf("accepted: %+v", result)
			}
		})
	}
}

func TestVerifyContainerRejectsReorderedEntries(t *testing.T) {
	entries := []containerEntry{{"case/analysis/a.json", []byte("a")}, {"case/manifest.json", []byte("{}")}}
	metadata, _, _ := containerFixture(t, entries)
	descriptor, _ := json.Marshal(metadata)
	raw := writeContainerFixture(t, descriptor, []containerEntry{entries[1], entries[0]})
	if _, err := VerifyContainer(context.Background(), bytes.NewReader(raw), DefaultLimits()); !errors.Is(err, ErrPayloadMismatch) {
		t.Fatalf("reordered inventory accepted: %v", err)
	}
}

func TestVerifyContainerBudgets(t *testing.T) {
	_, data, firstPayload := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}\n")}})
	limits := DefaultLimits()
	limits.ContainerBytes = int64(len(data) - 1)
	reader := &countingReader{Reader: bytes.NewReader(data)}
	if _, err := VerifyContainer(context.Background(), reader, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("container limit: %v", err)
	}
	if reader.count > limits.ContainerBytes+1 {
		t.Fatalf("budget overread: %d", reader.count)
	}
	// io.ReadFull can suppress an error when the final read fills its buffer.
	// A Reader returning the last bytes together with EOF must not hide oversize.
	if _, err := VerifyContainer(context.Background(), &lastErrorReader{data: bytes.Clone(data), failure: io.EOF}, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("EOF alongside final bytes bypassed container budget: %v", err)
	}
	limits = DefaultLimits()
	limits.MetadataBytes = 1
	reader = &countingReader{Reader: bytes.NewReader(data)}
	if _, err := VerifyContainer(context.Background(), reader, limits); !errors.Is(err, ErrLimitExceeded) || reader.count != 512 {
		t.Fatalf("descriptor header limit: %v (%d bytes)", err, reader.count)
	}
	// A huge declared payload header is rejected without reading its body.
	raw := bytes.Clone(data)
	copy(raw[firstPayload+124:firstPayload+136], []byte("77777777777\x00"))
	fixHeaderChecksum(raw[firstPayload : firstPayload+512])
	reader = &countingReader{Reader: bytes.NewReader(raw)}
	if _, err := VerifyContainer(context.Background(), reader, DefaultLimits()); err == nil || reader.count != int64(firstPayload+512) {
		t.Fatalf("unbounded header was read: %v", err)
	}
}

type cancelContainerReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *cancelContainerReader) Read(data []byte) (int, error) {
	count, err := r.Reader.Read(data)
	r.cancel()
	return count, err
}

type noProgressReader struct{}

func (noProgressReader) Read([]byte) (int, error) { return 0, nil }

type lastErrorReader struct {
	data    []byte
	failure error
}

func (r *lastErrorReader) Read(data []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	count := copy(data, r.data)
	r.data = r.data[count:]
	if len(r.data) == 0 {
		return count, r.failure
	}
	return count, nil
}

func TestVerifyContainerCancellationAndIOErrors(t *testing.T) {
	_, data, _ := containerFixture(t, []containerEntry{{"case/manifest.json", []byte("{}")}})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyContainer(ctx, bytes.NewReader(data), DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel before read: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if _, err := VerifyContainer(ctx, &cancelContainerReader{Reader: bytes.NewReader(data), cancel: cancel}, DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel during read: %v", err)
	}
	failure := errors.New("fixture IO failure")
	for _, reader := range []io.Reader{failedReader{failure}, &lastErrorReader{data: bytes.Clone(data), failure: failure}, io.MultiReader(bytes.NewReader(data), failedReader{failure})} {
		if _, err := VerifyContainer(context.Background(), reader, DefaultLimits()); !errors.Is(err, failure) {
			t.Fatalf("IO failure lost: %v", err)
		}
	}
	if _, err := VerifyContainer(context.Background(), noProgressReader{}, DefaultLimits()); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("no-progress reader: %v", err)
	}
	if _, err := VerifyContainer(nil, bytes.NewReader(data), DefaultLimits()); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := VerifyContainer(context.Background(), nil, DefaultLimits()); !errors.Is(err, ErrInvalidContainer) {
		t.Fatalf("nil reader: %v", err)
	}
}

func FuzzVerifyContainer(f *testing.F) {
	_, data, _ := containerFixture(f, []containerEntry{{"case/manifest.json", []byte("{}\n")}})
	f.Add(data)
	f.Add(data[:512])
	f.Add(append(bytes.Clone(data), data...))
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := DefaultLimits()
		limits.ContainerBytes = 1 << 20
		result, err := VerifyContainer(context.Background(), bytes.NewReader(data), limits)
		if err == nil {
			if err := ValidateMetadata(result.Metadata, limits); err != nil {
				t.Fatalf("invalid verified metadata: %v", err)
			}
			if result.ContainerBytes != int64(len(data)) || result.ContainerBytes > limits.ContainerBytes || result.PayloadBytes > limits.PayloadBytes {
				t.Fatal("verification exceeded budget or ignored input")
			}
		} else if !reflect.DeepEqual(result, ContainerVerification{}) {
			t.Fatal("partial verification escaped on failure")
		}
	})
}
