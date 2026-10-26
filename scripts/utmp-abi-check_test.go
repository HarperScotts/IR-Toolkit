//go:build ignore

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func nativeProbeFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/utmp-abi/glibc-2.42-aarch64.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestUtmpNativeHeaderProbe(t *testing.T) {
	r, err := verifyABI(nativeProbeFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.Architecture != "aarch64" || r.LibcHeaders != "glibc-2.42" || r.RecordSize != 400 || r.Fields["seconds"].Size != 8 || r.Fields["address_bytes"].Offset != 360 {
		t.Fatalf("native measurement changed: %+v", r)
	}
	// Endian-neutral validation: reverse only integer bytes. This is a synthetic
	// validator regression, NOT acceptance of a real big-endian ABI profile.
	r.ByteOrder = "big"
	for at, encoded := range r.Samples {
		data, _ := hex.DecodeString(encoded)
		for name, f := range r.Fields {
			if name != "type" && name != "pid" && name != "session" && name != "seconds" && name != "microseconds" {
				continue
			}
			for i, j := f.Offset, f.Offset+f.Size-1; i < j; i, j = i+1, j-1 {
				data[i], data[j] = data[j], data[i]
			}
		}
		r.Samples[at] = hex.EncodeToString(data)
	}
	data, _ := json.Marshal(r)
	if _, err := verifyABI(data); err != nil {
		t.Fatal("synthetic big-endian sentinel", err)
	}
}

func TestUtmpProbeRejectsDriftAndMalformedReports(t *testing.T) {
	for name, mutate := range map[string]func(*abiReport){
		"schema":              func(r *abiReport) { r.Schema = "unknown" },
		"endian":              func(r *abiReport) { r.ByteOrder = "middle" },
		"record_limit":        func(r *abiReport) { r.RecordSize = 4097 },
		"alignment":           func(r *abiReport) { r.Alignment = 3 },
		"negative_offset":     func(r *abiReport) { f := r.Fields["type"]; f.Offset = -1; r.Fields["type"] = f },
		"overlap":             func(r *abiReport) { f := r.Fields["type"]; f.Offset = 4; r.Fields["type"] = f },
		"overflow":            func(r *abiReport) { f := r.Fields["type"]; f.Size = int(^uint(0) >> 1); r.Fields["type"] = f },
		"unsupported_width":   func(r *abiReport) { f := r.Fields["type"]; f.Size = 3; r.Fields["type"] = f },
		"wrong_offset":        func(r *abiReport) { f := r.Fields["pid"]; f.Offset = 380; r.Fields["pid"] = f },
		"wrong_width":         func(r *abiReport) { f := r.Fields["seconds"]; f.Size = 4; r.Fields["seconds"] = f },
		"signed_array":        func(r *abiReport) { f := r.Fields["line"]; f.Signed = true; r.Fields["line"] = f },
		"missing_field":       func(r *abiReport) { delete(r.Fields, "pid") },
		"unknown_field":       func(r *abiReport) { f := r.Fields["pid"]; delete(r.Fields, "pid"); r.Fields["other"] = f },
		"duplicate_constants": func(r *abiReport) { r.Constants["user_process"] = r.Constants["login_process"] },
		"missing_constant":    func(r *abiReport) { delete(r.Constants, "boot_time") },
		"sample_count":        func(r *abiReport) { r.Samples = r.Samples[:1] },
		"truncated_hex":       func(r *abiReport) { r.Samples[0] = r.Samples[0][:100] },
		"invalid_hex":         func(r *abiReport) { r.Samples[0] = "xx" + r.Samples[0][2:] },
		"numeric_sentinel":    func(r *abiReport) { r.Samples[0] = "0000" + r.Samples[0][4:] },
		"array_sentinel":      func(r *abiReport) { r.Samples[0] = r.Samples[0][:16] + "00" + r.Samples[0][18:] },
		"reserved_bytes":      func(r *abiReport) { r.Samples[0] = r.Samples[0][:4] + "ff" + r.Samples[0][6:] },
	} {
		t.Run(name, func(t *testing.T) {
			r, err := verifyABI(nativeProbeFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			data, _ := json.Marshal(r)
			if _, err := verifyABI(data); err == nil {
				t.Fatal("corrupt report accepted")
			}
		})
	}
	for _, data := range [][]byte{nil, []byte("null"), []byte(strings.Repeat(" ", 65537)), append(nativeProbeFixture(t), []byte("{}")...), []byte(`{"unrecognized":1}`)} {
		if _, err := verifyABI(data); err == nil {
			t.Fatal("malformed input accepted")
		}
	}
}

func FuzzUtmpABIReport(f *testing.F) {
	data, err := os.ReadFile("testdata/utmp-abi/glibc-2.42-aarch64.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) { _, _ = verifyABI(input) })
}
