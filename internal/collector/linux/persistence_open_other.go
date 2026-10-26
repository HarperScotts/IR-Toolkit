//go:build !linux

package linux

import "os"

// Non-Linux builds use synthetic regular-file fixtures only. Other platforms'
// collector factories never select the Linux collector.
func openPersistenceFile(root *os.Root, name string) (*os.File, error) { return root.Open(name) }
func persistenceOwner(info os.FileInfo) (*uint32, *uint32)             { return nil, nil }
