package archive

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Hash-only comparison isolates buffer allocation without changing Commit's
// copy+Sync path or claiming that its wall time is attributable to this alone.
func BenchmarkInventoryManyFiles(b *testing.B) {
	for _, count := range []int{256, 4096} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			root := b.TempDir()
			data := make([]byte, 512)
			for index := 0; index < count; index++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d.bin", index)), data, 0600); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				files, err := inventory(root, nil)
				if err != nil || len(files) != count {
					b.Fatalf("inventory count=%d: %v", len(files), err)
				}
			}
		})
	}
}

func BenchmarkInventoryCopySync(b *testing.B) {
	for _, count := range []int{256, 4096} {
		b.Run(fmt.Sprintf("files-%d", count), func(b *testing.B) {
			root := b.TempDir()
			parent := b.TempDir()
			data := make([]byte, 512)
			for index := 0; index < count; index++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d.bin", index)), data, 0600); err != nil {
					b.Fatal(err)
				}
			}
			var copied, synced, total time.Duration
			var syncCalls int
			observe := func(stage string, duration time.Duration) {
				if stage == "copy" {
					copied += duration
				} else if stage == "sync" {
					synced += duration
					syncCalls++
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				b.StopTimer()
				destination, err := os.MkdirTemp(parent, "copy-")
				if err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				started := time.Now()
				files, err := inventoryObserved(root, &destination, observe)
				total += time.Since(started)
				if err != nil || len(files) != count {
					b.Fatal(err)
				}
				b.StopTimer()
				if err := os.RemoveAll(destination); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
			}
			if syncCalls != count*b.N {
				b.Fatalf("sync calls=%d, expected=%d", syncCalls, count*b.N)
			}
			b.ReportMetric(float64(copied.Microseconds())/1000/float64(b.N), "copy-ms/op")
			b.ReportMetric(float64(synced.Microseconds())/1000/float64(b.N), "sync-ms/op")
			b.ReportMetric(float64((total-copied-synced).Microseconds())/1000/float64(b.N), "other-ms/op")
			b.ReportMetric(float64(syncCalls)/float64(b.N), "syncs/op")
		})
	}
}

func TestInventoryObserverPreservesBytesAndSyncCount(t *testing.T) {
	root := t.TempDir()
	parent := t.TempDir()
	for index := 0; index < 3; index++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%d.bin", index)), []byte(fmt.Sprintf("unchanged evidence %d", index)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := inventory(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	copyCalls, syncCalls := 0, 0
	observe := func(stage string, _ time.Duration) {
		if stage == "copy" {
			copyCalls++
		}
		if stage == "sync" {
			syncCalls++
		}
	}
	actual, err := inventoryObserved(root, &parent, observe)
	if err != nil || !reflect.DeepEqual(expected, actual) || copyCalls != 3 || syncCalls != 3 {
		t.Fatalf("observed copy changed: %v copies=%d syncs=%d", err, copyCalls, syncCalls)
	}
	persisted, err := inventory(parent, nil)
	if err != nil || !reflect.DeepEqual(expected, persisted) {
		t.Fatal("copy changed inventory", err)
	}
	for path := range expected {
		source, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		copied, err := os.ReadFile(filepath.Join(parent, path))
		if err != nil || !bytes.Equal(source, copied) {
			t.Fatal("observed copy changed raw bytes", err)
		}
	}
	syncCalls = 0
	if _, err := inventoryObserved(root, nil, observe); err != nil || syncCalls != 0 {
		t.Fatal("hash-only scan unexpectedly synced", err)
	}
}
