package analysiscommit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"sort"
	"strings"
	"testing"
)

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
const goldenDigest = "78e4f64a3a12b870ce1efaea1439c0347e688de2590fb401db7becdc5eec5275"

func fixtureRun() Run { return Run{RunFormat, FormatVersion, "0123456789abcdef0123456789abcdef"} }

func fixtureCommit() Commit {
	c := Commit{Format: CommitFormat, FormatVersion: FormatVersion, RunID: fixtureRun().RunID,
		ToolVersion: "test-tool-1", RulesVersion: "test-rules-1", HostID: "alpha", CollectionID: "collection-1", ContentDigest: goldenDigest}
	for _, path := range requiredInputs {
		c.Inputs = append(c.Inputs, File{path, 0, emptyHash})
	}
	sort.Slice(c.Inputs, func(i, j int) bool { return c.Inputs[i].Path < c.Inputs[j].Path })
	c.Files = append([]File(nil), c.Inputs...)
	for _, path := range outputs {
		c.Files = append(c.Files, File{path, 0, emptyHash})
	}
	c.Files = append(c.Files, File{RunPath, 99, "db64f9f225d56c1fd9565927f9cc5a823aceaf1d3b6a52586eee82906051447c"})
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
	return c
}

func seal(t testing.TB, c Commit) Commit {
	t.Helper()
	var err error
	c.ContentDigest, err = ContentDigest(c, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGoldenAndRoundTrip(t *testing.T) {
	// Independently computed with Node crypto + an explicitly field-ordered
	// JSON.stringify fixture (ASCII vector, 26 final entries, 99-byte run).
	c := fixtureCommit()
	if err := ValidatePair(fixtureRun(), c, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if got, err := ContentDigest(c, DefaultLimits()); err != nil || got != goldenDigest {
		t.Fatalf("golden=%s, %v", got, err)
	}
	data, err := EncodeCommit(c, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, pretty := range []bool{false, true} {
		wire := data
		if pretty {
			wire, err = json.MarshalIndent(c, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
		}
		got, err := ReadCommit(bytes.NewReader(wire), DefaultLimits())
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatalf("roundtrip: %+v, %v", got, err)
		}
	}
	runBytes, err := EncodeRun(fixtureRun(), DefaultLimits())
	if err != nil || len(runBytes) != 99 {
		t.Fatalf("run: %s, %v", runBytes, err)
	}
	run, err := ReadRun(bytes.NewReader(runBytes), DefaultLimits())
	if err != nil || run != fixtureRun() {
		t.Fatal(run, err)
	}
	run.RunID = strings.Repeat("f", 32)
	if !errors.Is(ValidatePair(run, c, DefaultLimits()), ErrInvalid) {
		t.Fatal("run mismatch accepted")
	}
}

func TestStrictCommitJSON(t *testing.T) {
	data, err := EncodeCommit(fixtureCommit(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	for name, changed := range map[string]string{
		"unknown":                strings.Replace(raw, `"format":`, `"extra":true,"format":`, 1),
		"duplicate escaped key":  strings.Replace(raw, `"format":`, `"f\u006frmat":"other","format":`, 1),
		"case alias":             strings.Replace(raw, `"host_id":`, `"Host_ID":`, 1),
		"missing field":          strings.Replace(raw, `"ioc":null,`, "", 1),
		"null required":          strings.Replace(raw, `"files":[`, `"files":null,"old":[`, 1),
		"null inventory":         strings.Replace(raw, `"inputs":[`, `"inputs":null,"old":[`, 1),
		"null scalar":            strings.Replace(raw, `"host_id":"alpha"`, `"host_id":null`, 1),
		"nested extra":           strings.Replace(raw, `"since":null`, `"since":null,"extra":0`, 1),
		"missing nullable bound": strings.Replace(raw, `"since":null,`, "", 1),
		"file duplicate":         strings.Replace(raw, `"size":0`, `"size":0,"s\u0069ze":1`, 1),
		"file unknown":           strings.Replace(raw, `"size":0`, `"size":0,"mode":777`, 1),
		"null size":              strings.Replace(raw, `"size":0`, `"size":null`, 1),
		"float size":             strings.Replace(raw, `"size":0`, `"size":0.0`, 1),
		"exponent size":          strings.Replace(raw, `"size":0`, `"size":0e0`, 1),
		"overflow":               strings.Replace(raw, `"size":0`, `"size":9223372036854775808`, 1),
		"string size":            strings.Replace(raw, `"size":0`, `"size":"0"`, 1),
		"bad UTF8":               strings.Replace(raw, "alpha", string([]byte{0xff}), 1),
		"high surrogate":         strings.Replace(raw, "alpha", `\ud800`, 1),
		"low surrogate":          strings.Replace(raw, "alpha", `\udc00`, 1),
		"wrong surrogate pair":   strings.Replace(raw, "alpha", `\ud800\u0041`, 1),
		"trailing JSON":          raw + `{}`, "trailing junk": raw + `x`, "truncated": raw[:len(raw)-1],
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ReadCommit(strings.NewReader(changed), DefaultLimits())
			if !errors.Is(err, ErrInvalid) || !reflect.DeepEqual(got, Commit{}) {
				t.Fatalf("accepted/wrong error: %+v %v", got, err)
			}
		})
	}
}

func TestCommitSemanticRejections(t *testing.T) {
	for name, change := range map[string]func(*Commit){
		"version":             func(c *Commit) { c.FormatVersion++ },
		"format":              func(c *Commit) { c.Format = RunFormat },
		"run ID":              func(c *Commit) { c.RunID = "short" },
		"identity whitespace": func(c *Commit) { c.HostID = " alpha" },
		"control":             func(c *Commit) { c.RulesVersion = "bad\nvalue" },
		"unknown time":        func(c *Commit) { s := "0001-01-01T00:00:00Z"; c.Window.Since = &s },
		"offset time":         func(c *Commit) { s := "2026-10-16T08:00:00+08:00"; c.Window.Since = &s },
		"reversed bounds":     func(c *Commit) { s, u := "2026-10-16T02:00:00Z", "2026-10-16T01:00:00Z"; c.Window = Window{&s, &u} },
		"missing output":      func(c *Commit) { c.Files = c.Files[1:] },
		"missing input":       func(c *Commit) { c.Inputs = c.Inputs[1:] },
		"unsorted":            func(c *Commit) { c.Files[0], c.Files[1] = c.Files[1], c.Files[0] },
		"negative":            func(c *Commit) { c.Files[0].Size = -1 },
		"uppercase hash":      func(c *Commit) { c.Files[0].SHA256 = strings.ToUpper(emptyHash) },
		"copied input changed": func(c *Commit) {
			for i := range c.Files {
				if c.Files[i].Path == "manifest.json" {
					c.Files[i].Size++
				}
			}
		},
		"unrecorded IOC": func(c *Commit) { c.IOC = &File{IOCPath, 0, emptyHash} },
		"self reference": func(c *Commit) {
			c.Files = append(c.Files, File{CommitPath, 0, emptyHash})
			sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := fixtureCommit()
			change(&c)
			if err := Validate(c, DefaultLimits()); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted/wrong error: %v", err)
			}
		})
	}
	c := fixtureCommit()
	c.HostID = "different"
	if !errors.Is(Validate(c, DefaultLimits()), ErrDigest) {
		t.Fatal("digest not binding identity")
	}
	if data, err := EncodeCommit(c, DefaultLimits()); !errors.Is(err, ErrDigest) || data != nil {
		t.Fatal("encoder silently repaired digest")
	}
}

func TestIOCAndUnicode(t *testing.T) {
	c := fixtureCommit()
	ioc := File{IOCPath, 3, emptyHash} // Declarations are not actual-byte validation.
	c.IOC = &ioc
	c.Inputs = append(c.Inputs, ioc)
	c.Files = append(c.Files, ioc)
	sort.Slice(c.Inputs, func(i, j int) bool { return c.Inputs[i].Path < c.Inputs[j].Path })
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
	c.HostID = "host-😀-�-<>&"
	c = seal(t, c)
	data, err := EncodeCommit(c, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	data = bytes.ReplaceAll(data, []byte("😀"), []byte(`\ud83d\ude00`))
	got, err := ReadCommit(bytes.NewReader(data), DefaultLimits())
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("Unicode/IOC: %+v %v", got, err)
	}
	c.IOC = nil
	if !errors.Is(Validate(c, DefaultLimits()), ErrInvalid) {
		t.Fatal("IOC absent state inconsistent")
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestLimitsAndReaderErrors(t *testing.T) {
	data, err := EncodeRun(fixtureRun(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	l := DefaultLimits()
	l.MetadataBytes = int64(len(data))
	if _, err := ReadRun(bytes.NewReader(data), l); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadRun(bytes.NewReader(append(data, ' ')), l); !errors.Is(err, ErrLimit) || got != (Run{}) {
		t.Fatal(got, err)
	}
	sentinel := errors.New("read sentinel")
	if _, err := ReadCommit(failingReader{sentinel}, DefaultLimits()); !errors.Is(err, sentinel) {
		t.Fatal("lost reader error", err)
	}
	if _, err := ReadRun(nil, DefaultLimits()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	c := fixtureCommit()
	wire, err := EncodeCommit(c, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	l = DefaultLimits()
	l.PayloadBytes = int64(len(wire)) + 99
	if _, err := EncodeCommit(c, l); err != nil {
		t.Fatal("exact payload cap", err)
	}
	l.PayloadBytes--
	if _, err := ReadCommit(bytes.NewReader(wire), l); !errors.Is(err, ErrLimit) {
		t.Fatal("commit bytes not counted", err)
	}
	l = DefaultLimits()
	l.FileCount = len(c.Files)
	if !errors.Is(Validate(c, l), ErrLimit) {
		t.Fatal("completion marker slot not counted")
	}
	l = DefaultLimits()
	l.FileBytes = 98
	if !errors.Is(Validate(c, l), ErrLimit) {
		t.Fatal("file size cap ignored")
	}
	l = DefaultLimits()
	l.MetadataBytes++
	if _, err := ReadCommit(strings.NewReader(""), l); !errors.Is(err, ErrLimit) {
		t.Fatal("enlarged limits accepted")
	}
	if _, err := ReadRun(io.LimitReader(strings.NewReader("{}"), 1), DefaultLimits()); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestInventoryPathsAndAliases(t *testing.T) {
	for _, paths := range [][]string{
		{"Analysis-Commit.json"}, {"Analysis-Run.json"}, {"analysis/IOC_Matches.json"},
		{"analysis-commit.json/child"}, {"analysis-run.json/child"}, {"analysis/ioc_matches.json/child"},
		{"../escape"}, {"C:/escape"}, {"a\\b"}, {"NUL.txt"}, {"aux/x"}, {"a/COM1.json"}, {".hidden"}, {"a."}, {"é"},
		{"A/x", "a/y"}, {"a", "a/b"}, {"a", "a"}, {"b", "a"},
	} {
		var files []File
		for _, p := range paths {
			files = append(files, File{p, 0, emptyHash})
		}
		if _, err := validateFiles(files, DefaultLimits()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %v: %v", paths, err)
		}
	}
}

func TestStrictRunJSON(t *testing.T) {
	data, err := EncodeRun(fixtureRun(), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(data)
	for _, changed := range []string{
		strings.Replace(raw, `"format":`, `"Format":`, 1),
		strings.Replace(raw, `"run_id":`, `"run_id":"other","run_id":`, 1),
		strings.Replace(raw, `"run_id":`, `"r\u0075n_id":"other","run_id":`, 1),
		strings.Replace(raw, `"format_version":1`, `"format_version":1.0`, 1),
		strings.Replace(raw, `"format_version":1`, `"format_version":2`, 1),
		strings.Replace(raw, `"format_version":1`, `"format_version":null`, 1),
		strings.Replace(raw, fixtureRun().RunID, strings.Repeat("A", 32), 1),
		`{}`, `null`, raw + `{}`,
	} {
		got, err := ReadRun(strings.NewReader(changed), DefaultLimits())
		if !errors.Is(err, ErrInvalid) || got != (Run{}) {
			t.Fatalf("run accepted: %+v, %v", got, err)
		}
	}
}

func TestCanonicalWindowAndAuxiliaryPreservation(t *testing.T) {
	for _, bounds := range []Window{
		{}, {Since: stringPointer("2026-10-16T00:00:00Z")}, {Until: stringPointer("2026-10-16T01:00:00.0000001Z")},
		{Since: stringPointer("2026-10-16T00:00:00Z"), Until: stringPointer("2026-10-16T00:00:00Z")},
	} {
		c := fixtureCommit()
		c.Window = bounds
		aux := File{"raw/extra.json", 2, emptyHash}
		c.Inputs = append(c.Inputs, aux)
		c.Files = append(c.Files, aux)
		sort.Slice(c.Inputs, func(i, j int) bool { return c.Inputs[i].Path < c.Inputs[j].Path })
		sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
		c = seal(t, c)
		encoded, err := EncodeCommit(c, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadCommit(bytes.NewReader(encoded), DefaultLimits())
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatal(err)
		}
		c.Files = append(c.Files, File{"raw/undeclared.json", 0, emptyHash})
		sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
		if !errors.Is(Validate(c, DefaultLimits()), ErrInvalid) {
			t.Fatal("undeclared auxiliary accepted")
		}
	}
}

func stringPointer(s string) *string { return &s }

func TestGeneratedInputCanBeRebuiltButIOCMustBeCopied(t *testing.T) {
	c := fixtureCommit()
	c.Inputs = append(c.Inputs, File{"analysis/report.json", 7, emptyHash})
	sort.Slice(c.Inputs, func(i, j int) bool { return c.Inputs[i].Path < c.Inputs[j].Path })
	c = seal(t, c)
	if err := Validate(c, DefaultLimits()); err != nil {
		t.Fatal("old generated output may be rebuilt", err)
	}
	ioc := File{IOCPath, 2, emptyHash}
	c.IOC = &ioc
	c.Inputs = append(c.Inputs, ioc)
	c.Files = append(c.Files, ioc)
	sort.Slice(c.Inputs, func(i, j int) bool { return c.Inputs[i].Path < c.Inputs[j].Path })
	sort.Slice(c.Files, func(i, j int) bool { return c.Files[i].Path < c.Files[j].Path })
	c = seal(t, c)
	for i := range c.Files {
		if c.Files[i].Path == IOCPath {
			c.Files[i].Size++
		}
	}
	if !errors.Is(Validate(c, DefaultLimits()), ErrInvalid) {
		t.Fatal("copied IOC changed")
	}
}

type countedReader struct {
	io.Reader
	count int
}

func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.count += n
	return n, err
}

func TestMetadataReaderStopsAtBudgetPlusOne(t *testing.T) {
	l := DefaultLimits()
	l.MetadataBytes = 128
	r := &countedReader{Reader: strings.NewReader(strings.Repeat(" ", 4096))}
	if _, err := ReadCommit(r, l); !errors.Is(err, ErrLimit) || r.count != 129 {
		t.Fatalf("read %d: %v", r.count, err)
	}
}

func FuzzReadRun(f *testing.F) {
	data, _ := json.Marshal(fixtureRun())
	f.Add(data)
	f.Add([]byte(`{"run_id":"\ud800"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		run, err := ReadRun(bytes.NewReader(data), DefaultLimits())
		if err != nil {
			if run != (Run{}) {
				t.Fatal("partial run on failure")
			}
			return
		}
		encoded, err := EncodeRun(run, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadRun(bytes.NewReader(encoded), DefaultLimits())
		if err != nil || got != run {
			t.Fatal("unstable run", err)
		}
	})
}

func FuzzReadCommit(f *testing.F) {
	data, _ := json.Marshal(fixtureCommit())
	f.Add(data)
	f.Add([]byte(`{"window":{"since":null}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ReadCommit(bytes.NewReader(data), DefaultLimits())
		if err != nil {
			if !reflect.DeepEqual(c, Commit{}) {
				t.Fatal("partial commit on failure")
			}
			return
		}
		encoded, err := EncodeCommit(c, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		got, err := ReadCommit(bytes.NewReader(encoded), DefaultLimits())
		if err != nil || !reflect.DeepEqual(got, c) {
			t.Fatal("unstable roundtrip", err)
		}
	})
}
