// Package analysiscommit validates bounded analysis completion declarations.
// It does not read case files, load domains, publish results or authenticate a
// source. It is not yet wired into CLI, Store or package readers.
package analysiscommit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	RunFormat     = "ir-toolkit.analysis-run"
	CommitFormat  = "ir-toolkit.analysis-commit"
	FormatVersion = 1
	RunPath       = "analysis-run.json"
	CommitPath    = "analysis-commit.json"
	IOCPath       = "analysis/ioc_matches.json"
)

var (
	ErrInvalid = errors.New("invalid analysis completion declaration")
	ErrLimit   = errors.New("analysis completion limit exceeded")
	ErrDigest  = errors.New("analysis completion digest mismatch")
)

type Limits struct {
	MetadataBytes           int64
	FileCount               int
	FileBytes, PayloadBytes int64
}

func DefaultLimits() Limits { return Limits{1 << 20, 4096, 64 << 20, 256 << 20} }

func (l Limits) validate() error {
	d := DefaultLimits()
	if l.MetadataBytes <= 0 || l.MetadataBytes > d.MetadataBytes || l.FileCount <= 0 || l.FileCount > d.FileCount || l.FileBytes <= 0 || l.FileBytes > d.FileBytes || l.PayloadBytes <= 0 || l.PayloadBytes > d.PayloadBytes {
		return ErrLimit
	}
	return nil
}

type Run struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"format_version"`
	RunID         string `json:"run_id"`
}

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Bounds use canonical UTC RFC3339Nano strings or explicit null (unbounded).
type Window struct {
	Since *string `json:"since"`
	Until *string `json:"until"`
}

type Commit struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"format_version"`
	RunID         string `json:"run_id"`
	ToolVersion   string `json:"tool_version"`
	RulesVersion  string `json:"rules_version"`
	HostID        string `json:"host_id"`
	CollectionID  string `json:"collection_id"`
	Window        Window `json:"window"`
	Inputs        []File `json:"inputs"`
	IOC           *File  `json:"ioc"`
	Files         []File `json:"files"`
	ContentDigest string `json:"content_digest"`
}

var outputs = [...]string{
	"analysis/activity_analysis.json", "analysis/file_analysis.json", "analysis/historical_correlation.json",
	"analysis/login_analysis.json", "analysis/network_analysis.json", "analysis/persistence_analysis.json",
	"analysis/powershell_analysis.json", "analysis/process_history_analysis.json", "analysis/process_relationship_analysis.json",
	"analysis/report.json", "analysis/report.txt", "analysis/windows_event_analysis.json", "timeline/events.jsonl", "timeline/timeline.json",
}

var requiredInputs = [...]string{
	"manifest.json", "host/host.json", "capabilities/capabilities.json", "process/processes.json",
	"network/network.json", "login/login.json", "files/files.json", "persistence/persistence.json",
	"events/process_events.json", "events/powershell_events.json", "events/windows_events.json",
}

func identity(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func ValidateRun(run Run) error {
	if run.Format != RunFormat || run.FormatVersion != FormatVersion || !lowerHex(run.RunID, 32) {
		return ErrInvalid
	}
	return nil
}

func windowTime(value *string) (time.Time, error) {
	if value == nil {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, *value)
	if err != nil || t.IsZero() || t.UTC().Format(time.RFC3339Nano) != *value {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

// Validate checks declarations only, not actual bytes or Analyzer correctness.
func Validate(commit Commit, limits Limits) error {
	if err := validateFields(commit, limits); err != nil {
		return err
	}
	if !lowerHex(commit.ContentDigest, 64) {
		return ErrInvalid
	}
	digest, err := ContentDigest(commit, limits)
	if err != nil {
		return err
	}
	if digest != commit.ContentDigest {
		return ErrDigest
	}
	return nil
}

func validateFields(c Commit, l Limits) error {
	if err := l.validate(); err != nil {
		return err
	}
	if c.Format != CommitFormat || c.FormatVersion != FormatVersion || !lowerHex(c.RunID, 32) {
		return ErrInvalid
	}
	for _, v := range []string{c.ToolVersion, c.RulesVersion, c.HostID, c.CollectionID} {
		if !identity(v) {
			return ErrInvalid
		}
	}
	since, err := windowTime(c.Window.Since)
	if err != nil {
		return err
	}
	until, err := windowTime(c.Window.Until)
	if err != nil || c.Window.Since != nil && c.Window.Until != nil && since.After(until) {
		return ErrInvalid
	}
	inputs, err := validateFiles(c.Inputs, l)
	if err != nil {
		return err
	}
	files, err := validateFiles(c.Files, l)
	if err != nil {
		return err
	}
	// The completion file itself also consumes a package inventory slot.
	if len(c.Files) >= l.FileCount {
		return ErrLimit
	}
	for _, p := range requiredInputs {
		if _, ok := inputs[p]; !ok {
			return fmt.Errorf("%w: required input %s", ErrInvalid, p)
		}
	}
	generated := map[string]bool{}
	for _, p := range outputs {
		generated[p] = true
		if _, ok := files[p]; !ok {
			return fmt.Errorf("%w: required output %s", ErrInvalid, p)
		}
	}
	if _, ok := inputs[RunPath]; ok {
		return ErrInvalid
	}
	if _, ok := inputs[CommitPath]; ok {
		return ErrInvalid
	}
	if _, ok := files[CommitPath]; ok {
		return ErrInvalid
	}
	if _, ok := files[RunPath]; !ok {
		return ErrInvalid
	}
	for p, input := range inputs {
		output, ok := files[p]
		if !ok || !generated[p] && input != output {
			return fmt.Errorf("%w: changed/missing copied input %s", ErrInvalid, p)
		}
	}
	for p := range files {
		if _, ok := inputs[p]; !ok && !generated[p] && p != RunPath {
			return fmt.Errorf("%w: undeclared final file %s", ErrInvalid, p)
		}
	}
	ioc, present := inputs[IOCPath]
	if (c.IOC != nil) != present || present && *c.IOC != ioc {
		return fmt.Errorf("%w: IOC presence/reference", ErrInvalid)
	}
	return nil
}

// ContentDigest ignores ContentDigest itself. It hashes a fixed domain prefix
// then compact encoding/json of the field-ordered Commit with that field set
// to the empty string. Inventories must already be strictly sorted, not sorted
// here. Go JSON escaping is part of this v1 codec (including HTML escapes).
func ContentDigest(commit Commit, limits Limits) (string, error) {
	if err := validateFields(commit, limits); err != nil {
		return "", err
	}
	commit.ContentDigest = ""
	data, err := json.Marshal(commit)
	if err != nil {
		return "", err
	}
	if int64(len(data))+64 > limits.MetadataBytes {
		return "", ErrLimit
	}
	sum := sha256.Sum256(append([]byte("ir-toolkit.analysis-commit.digest.v1\n"), data...))
	return hex.EncodeToString(sum[:]), nil
}

// ValidatePair compares run declarations; filesystem verification must still
// hash the actual run file and every inventory entry before opening a view.
func ValidatePair(run Run, commit Commit, limits Limits) error {
	if err := ValidateRun(run); err != nil {
		return err
	}
	if err := Validate(commit, limits); err != nil {
		return err
	}
	if run.RunID != commit.RunID {
		return fmt.Errorf("%w: run ID mismatch", ErrInvalid)
	}
	return nil
}
