package packageio

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

type sourceInfoWithoutKey struct{ fs.FileInfo }

func (info sourceInfoWithoutKey) Sys() any { return nil }

type pairwiseSourceIndex []fs.FileInfo

func (index *pairwiseSourceIndex) add(info fs.FileInfo) bool {
	for _, previous := range *index {
		if os.SameFile(previous, info) {
			return true
		}
	}
	*index = append(*index, info)
	return false
}

func TestSourceIdentityIndexMatchesPairwise(t *testing.T) {
	root := t.TempDir()
	var infos []fs.FileInfo
	for n := range 12 {
		path := filepath.Join(root, fmt.Sprintf("file-%02d", n))
		if err := os.WriteFile(path, []byte("equal size and contents"), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		infos = append(infos, info, sourceInfoWithoutKey{info})
		// Exposing a native Sys on a wrapper must not create a false alias:
		// SameFile only recognizes FileInfo returned by os.Stat/Lstat.
		infos = append(infos, struct{ fs.FileInfo }{info})
	}
	alias := filepath.Join(root, "alias")
	if err := os.Link(filepath.Join(root, "file-00"), alias); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(alias)
	if err != nil {
		t.Fatal(err)
	}
	infos = append(infos, info)
	// The same inode observed with different sizes must still be an alias.
	if err := os.WriteFile(alias, []byte("mutated"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(alias)
	if err != nil {
		t.Fatal(err)
	}
	infos = append(infos, info)
	for seed := range int64(100) {
		var indexed sourceIdentityIndex
		var reference pairwiseSourceIndex
		for _, position := range rand.New(rand.NewSource(seed)).Perm(len(infos)) {
			if got, want := indexed.add(infos[position]), reference.add(infos[position]); got != want {
				t.Fatalf("seed %d position %d: indexed=%v pairwise=%v", seed, position, got, want)
			}
		}
	}
	// Exercise a previously unkeyed native FileInfo against a native key.
	var indexed sourceIdentityIndex
	indexed.fallback = []fs.FileInfo{info}
	if !indexed.add(info) {
		t.Fatal("missed fallback alias")
	}
}

func TestScanSourceRejectsLateHardLink(t *testing.T) {
	root := t.TempDir()
	for n := range 256 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("a%03d.bin", n)), []byte("same"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scanSource(context.Background(), root, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(root, "a000.bin"), filepath.Join(root, "z-alias.bin")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanSource(context.Background(), root, DefaultLimits()); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("hard link: %v", err)
	}
}

func BenchmarkSourceIdentityIndex(b *testing.B) {
	for _, count := range []int{256, 4096} {
		root := b.TempDir()
		var infos []fs.FileInfo
		for n := range count {
			path := filepath.Join(root, fmt.Sprintf("a%04d.bin", n))
			if err := os.WriteFile(path, []byte("same"), 0600); err != nil {
				b.Fatal(err)
			}
			info, err := os.Stat(path)
			if err != nil {
				b.Fatal(err)
			}
			infos = append(infos, info)
		}
		for _, indexed := range []bool{false, true} {
			name := "pairwise-reference"
			if indexed {
				name = "identity-index"
			}
			b.Run(fmt.Sprintf("%s-%d", name, count), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var index sourceIdentityIndex
					var reference pairwiseSourceIndex
					for _, info := range infos {
						var alias bool
						if indexed {
							alias = index.add(info)
						} else {
							alias = reference.add(info)
						}
						if alias {
							b.Fatal("unexpected alias")
						}
					}
				}
			})
		}
	}
}
