package packageio

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
)

// Focused allocation benchmark; run explicitly with -bench and -benchmem.
// Export still performs both content passes and all source/path checks.
func BenchmarkExportManyFiles(b *testing.B) {
	for _, count := range []int{256, 4096} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			root, original := exportFixture(b)
			for index := 0; index < count-len(original); index++ {
				writeExportFixture(b, root, fmt.Sprintf("z/%04d.bin", index), make([]byte, 512))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, err := ExportCase(context.Background(), root, "benchmark", io.Discard, DefaultLimits())
				if err != nil || len(result.Metadata.Files) != count {
					b.Fatalf("export count=%d: %v", len(result.Metadata.Files), err)
				}
			}
		})
	}
}

func BenchmarkScanSource(b *testing.B) {
	for _, count := range []int{256, 4096} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			root, original := exportFixture(b)
			for index := 0; index < count-len(original); index++ {
				writeExportFixture(b, root, fmt.Sprintf("z/%04d.bin", index), make([]byte, 512))
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				nodes, err := scanSource(context.Background(), root, DefaultLimits())
				if err != nil || len(nodes) < count {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMetadataStages(b *testing.B) {
	for _, count := range []int{256, 4096} {
		metadata := fixtureMetadata()
		metadata.Files = []File{{Path: "manifest.json", Size: 0, SHA256: emptySHA}}
		for index := 1; index < count; index++ {
			metadata.Files = append(metadata.Files, File{Path: fmt.Sprintf("z/%04d.bin", index), Size: 0, SHA256: emptySHA})
		}
		var err error
		metadata.ContentDigest, err = ContentDigest(metadata, DefaultLimits())
		if err != nil {
			b.Fatal(err)
		}
		encoded, err := json.Marshal(metadata)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(fmt.Sprintf("read-%d", count), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				result, err := ReadMetadata(bytes.NewReader(encoded), DefaultLimits())
				if err != nil || len(result.Files) != count {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("validate-%d", count), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := ValidateMetadata(metadata, DefaultLimits()); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Reference allocates the previous 32 KiB buffer per file/pass, without changing
// production paths. This isolates the allocation improvement from disk sampling.
func BenchmarkCopySourceBuffers(b *testing.B) {
	for _, reuse := range []bool{false, true} {
		name := "per-file-reference"
		if reuse {
			name = "operation-local"
		}
		b.Run(name, func(b *testing.B) {
			root, _ := exportFixture(b)
			for index := 0; index < 256; index++ {
				writeExportFixture(b, root, fmt.Sprintf("z/%04d.bin", index), make([]byte, 512))
			}
			nodes, err := scanSource(context.Background(), root, DefaultLimits())
			if err != nil {
				b.Fatal(err)
			}
			var buffer []byte
			if reuse {
				buffer = make([]byte, 32<<10)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				for range 2 {
					for _, node := range nodes {
						if !node.info.Mode().IsRegular() {
							continue
						}
						if !reuse {
							buffer = make([]byte, 32<<10)
						}
						if hash, err := copySource(context.Background(), root, node, io.Discard, buffer); err != nil || hash == "" {
							b.Fatal(err)
						}
					}
				}
			}
		})
	}
}
