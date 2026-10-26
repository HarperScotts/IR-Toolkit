//go:build ignore

// Developer-only stdin validator for utmp-abi-probe.c. No production decoder
// imports this tool; successful validation does not identify a file's writer.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type abiField struct {
	Offset int  `json:"offset"`
	Size   int  `json:"size"`
	Signed bool `json:"signed"`
}

type abiReport struct {
	Schema       string              `json:"schema"`
	Architecture string              `json:"architecture"`
	ByteOrder    string              `json:"byte_order"`
	LibcHeaders  string              `json:"libc_headers"`
	RecordSize   int                 `json:"record_size"`
	Alignment    int                 `json:"alignment"`
	Fields       map[string]abiField `json:"fields"`
	Constants    map[string]int      `json:"constants"`
	Samples      []string            `json:"samples"`
}

func verifyABI(data []byte) (abiReport, error) {
	var r abiReport
	if len(data) > 65536 {
		return r, fmt.Errorf("probe report exceeds 64 KiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return r, fmt.Errorf("trailing JSON data")
	}
	if r.Schema != "ir-utmp-abi-probe-v1" || (r.ByteOrder != "little" && r.ByteOrder != "big") || r.Architecture == "" || r.LibcHeaders == "" {
		return r, fmt.Errorf("invalid schema, byte order or environment labels")
	}
	if r.RecordSize < 1 || r.RecordSize > 4096 || r.Alignment < 1 || r.Alignment > r.RecordSize || r.Alignment&(r.Alignment-1) != 0 || r.RecordSize%r.Alignment != 0 || len(r.Samples) != 2 {
		return r, fmt.Errorf("invalid record size, alignment or sample count")
	}
	positive := map[string]uint64{"type": 0x1234, "pid": 0x01020304, "session": 0x10203040, "seconds": 1700000000, "microseconds": 123456}
	negative := map[string]int64{"type": -1, "pid": -2, "session": -3, "seconds": -4, "microseconds": -5}
	seeds := map[string]byte{"line": 11, "id": 22, "user": 33, "host": 44, "address_bytes": 55}
	if len(r.Fields) != len(positive)+len(seeds) {
		return r, fmt.Errorf("unexpected field set")
	}
	occupied := make([]bool, r.RecordSize)
	for name, field := range r.Fields {
		_, numeric := positive[name]
		_, array := seeds[name]
		if (!numeric && !array) || field.Offset < 0 || field.Size <= 0 || field.Offset > r.RecordSize || field.Size > r.RecordSize-field.Offset {
			return r, fmt.Errorf("invalid field %s", name)
		}
		if numeric && (field.Size != 2 && field.Size != 4 && field.Size != 8) {
			return r, fmt.Errorf("unsupported integer width: %s", name)
		}
		if array && field.Signed {
			return r, fmt.Errorf("array field marked scalar signed: %s", name)
		}
		for at := field.Offset; at < field.Offset+field.Size; at++ {
			if occupied[at] {
				return r, fmt.Errorf("overlapping field %s", name)
			}
			occupied[at] = true
		}
	}
	if len(r.Constants) != 4 {
		return r, fmt.Errorf("unexpected constants")
	}
	seen := map[int]bool{}
	for _, name := range []string{"user_process", "login_process", "dead_process", "boot_time"} {
		value, ok := r.Constants[name]
		if !ok || value <= 0 || value > 32767 || seen[value] {
			return r, fmt.Errorf("invalid constant %s", name)
		}
		seen[value] = true
	}
	var order binary.ByteOrder = binary.LittleEndian
	if r.ByteOrder == "big" {
		order = binary.BigEndian
	}
	for sampleIndex, encoded := range r.Samples {
		if len(encoded) != r.RecordSize*2 {
			return r, fmt.Errorf("incorrect sample length")
		}
		sample, err := hex.DecodeString(encoded)
		if err != nil {
			return r, fmt.Errorf("sample hex: %w", err)
		}
		for name, field := range r.Fields {
			got := sample[field.Offset : field.Offset+field.Size]
			if seed, array := seeds[name]; array {
				for i, value := range got {
					if value != seed+byte(17*i) {
						return r, fmt.Errorf("array sentinel mismatch: %s", name)
					}
				}
				continue
			}
			var value uint64
			switch field.Size {
			case 2:
				value = uint64(order.Uint16(got))
			case 4:
				value = uint64(order.Uint32(got))
			case 8:
				value = order.Uint64(got)
			}
			want := positive[name]
			if sampleIndex == 1 {
				want = uint64(negative[name])
				if field.Size < 8 {
					want &= (uint64(1) << (field.Size * 8)) - 1
				}
			}
			if value != want {
				return r, fmt.Errorf("integer sentinel mismatch: %s sample %d", name, sampleIndex)
			}
		}
		for at, used := range occupied {
			if !used && sample[at] != 0 {
				return r, fmt.Errorf("unexpected nonzero padding/reserved bytes")
			}
		}
	}
	return r, nil
}

func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/utmp-abi-check.go < probe.json")
		os.Exit(2)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	var r abiReport
	if err == nil {
		r, err = verifyABI(data)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ABI probe validation failed:", err)
		os.Exit(1)
	}
	summary := struct {
		Scope  string    `json:"scope"`
		SHA256 string    `json:"probe_report_sha256"`
		Report abiReport `json:"measured_report"`
	}{"synthetic ABI self-consistency only; not writer provenance, a production profile, current sessions or decoded historical evidence", fmt.Sprintf("%x", sha256.Sum256(data)), r}
	if err := json.NewEncoder(os.Stdout).Encode(summary); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
