// Package packageio exports and validates bounded offline USTAR packages. It does
// not load investigation domains, authenticate senders or publish views. Extraction
// only writes to a newly created temporary tree under a trusted parent.
package packageio

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	Format        = "ir-toolkit.case-package"
	FormatVersion = 1
	Profile       = "analyzed-case-v1"
)

var (
	ErrInvalidMetadata = errors.New("invalid package metadata")
	ErrInvalidPath     = errors.New("invalid package payload path")
	ErrLimitExceeded   = errors.New("package limit exceeded")
	ErrDigestMismatch  = errors.New("package content digest mismatch")
)

type File struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type Metadata struct {
	Format        string `json:"format"`
	FormatVersion int    `json:"format_version"`
	Profile       string `json:"profile"`
	HostID        string `json:"host_id"`
	Version       string `json:"version"`
	CaseName      string `json:"case_name"`
	ContentDigest string `json:"content_digest"`
	Files         []File `json:"files"`
}

// Limits may tighten v1 budgets, but cannot silently enlarge them. ContainerBytes
// is enforced by VerifyContainer; metadata validation alone cannot measure
// actual payload/container bytes or guarantee a memory ceiling.
type Limits struct {
	MetadataBytes  int64
	FileCount      int
	FileBytes      int64
	PayloadBytes   int64
	ContainerBytes int64
}

func DefaultLimits() Limits {
	return Limits{MetadataBytes: 1 << 20, FileCount: 4096, FileBytes: 64 << 20, PayloadBytes: 256 << 20, ContainerBytes: 272 << 20}
}

func (l Limits) validate() error {
	defaults := DefaultLimits()
	if l.MetadataBytes <= 0 || l.MetadataBytes > defaults.MetadataBytes ||
		l.FileCount <= 0 || l.FileCount > defaults.FileCount ||
		l.FileBytes <= 0 || l.FileBytes > defaults.FileBytes ||
		l.PayloadBytes <= 0 || l.PayloadBytes > defaults.PayloadBytes ||
		l.ContainerBytes <= 0 || l.ContainerBytes > defaults.ContainerBytes {
		return fmt.Errorf("%w: invalid v1 limits", ErrLimitExceeded)
	}
	return nil
}

// ReadMetadata reads at most MetadataBytes+1 bytes and strictly decodes a single
// descriptor. Successful validation only confirms declarations and their digest,
// not actual file bytes, completeness of analysis or source authenticity.
func ReadMetadata(reader io.Reader, limits Limits) (Metadata, error) {
	if err := limits.validate(); err != nil {
		return Metadata{}, err
	}
	if reader == nil {
		return Metadata{}, fmt.Errorf("%w: reader required", ErrInvalidMetadata)
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MetadataBytes+1))
	if err != nil {
		return Metadata{}, fmt.Errorf("read package metadata: %w", err)
	}
	if int64(len(data)) > limits.MetadataBytes {
		return Metadata{}, fmt.Errorf("%w: metadata bytes", ErrLimitExceeded)
	}
	if !utf8.Valid(data) || !validJSONEscapes(data) {
		return Metadata{}, fmt.Errorf("%w: invalid Unicode", ErrInvalidMetadata)
	}
	top, err := readObject(data, []string{"format", "format_version", "profile", "host_id", "version", "case_name", "content_digest", "files"})
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	fields := []struct {
		key    string
		target any
	}{
		{"format", &metadata.Format}, {"format_version", &metadata.FormatVersion},
		{"profile", &metadata.Profile}, {"host_id", &metadata.HostID}, {"version", &metadata.Version},
		{"case_name", &metadata.CaseName}, {"content_digest", &metadata.ContentDigest},
	}
	for _, field := range fields {
		if err := json.Unmarshal(top[field.key], field.target); err != nil {
			return Metadata{}, fmt.Errorf("%w: %s", ErrInvalidMetadata, field.key)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(top["files"]))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return Metadata{}, fmt.Errorf("%w: files array required", ErrInvalidMetadata)
	}
	for decoder.More() {
		if len(metadata.Files) >= limits.FileCount {
			return Metadata{}, fmt.Errorf("%w: file count", ErrLimitExceeded)
		}
		file, err := readFileEntry(decoder)
		if err != nil {
			return Metadata{}, err
		}
		metadata.Files = append(metadata.Files, file)
	}
	if _, err := decoder.Token(); err != nil {
		return Metadata{}, fmt.Errorf("%w: files closing delimiter", ErrInvalidMetadata)
	}
	if err := ValidateMetadata(metadata, limits); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

// readFileEntry shares the array decoder instead of allocating a raw object,
// field map and decoder per file. UseNumber preserves exact int64 syntax/range.
// The caller checks Unicode on the complete descriptor before decoding.
func readFileEntry(decoder *json.Decoder) (File, error) {
	invalid := func() (File, error) {
		return File{}, fmt.Errorf("%w: files entry", ErrInvalidMetadata)
	}
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return invalid()
	}
	var file File
	var seen uint8
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return invalid()
		}
		var bit uint8
		switch key {
		case "path":
			bit = 1
		case "size":
			bit = 2
		case "sha256":
			bit = 4
		default:
			return invalid()
		}
		if seen&bit != 0 {
			return invalid()
		}
		seen |= bit
		value, err := decoder.Token()
		if err != nil {
			return invalid()
		}
		if bit == 2 {
			number, ok := value.(json.Number)
			if !ok {
				return invalid()
			}
			file.Size, err = strconv.ParseInt(string(number), 10, 64)
			if err != nil {
				return invalid()
			}
		} else {
			value, ok := value.(string)
			if !ok {
				return invalid()
			}
			if bit == 1 {
				file.Path = value
			} else {
				file.SHA256 = value
			}
		}
	}
	token, err = decoder.Token()
	if err != nil || token != json.Delim('}') || seen != 7 {
		return invalid()
	}
	return file, nil
}

// readObject enforces exact, case-sensitive fields, including duplicate keys
// written using JSON escapes. All fields are required and null is forbidden.
func readObject(data []byte, required []string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("%w: object required", ErrInvalidMetadata)
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: object key", ErrInvalidMetadata)
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, fmt.Errorf("%w: unknown field %q", ErrInvalidMetadata, key)
		}
		if _, exists := fields[key]; exists {
			return nil, fmt.Errorf("%w: duplicate field %q", ErrInvalidMetadata, key)
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil, fmt.Errorf("%w: invalid field %q", ErrInvalidMetadata, key)
		}
		fields[key] = raw
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("%w: object closing delimiter", ErrInvalidMetadata)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidMetadata)
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("%w: missing field %q", ErrInvalidMetadata, key)
		}
	}
	return fields, nil
}

// encoding/json replaces unpaired escaped surrogates with U+FFFD. Reject them
// before decoding rather than silently changing package identity strings.
func validJSONEscapes(data []byte) bool {
	inString := false
	for index := 0; index < len(data); index++ {
		if data[index] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[index] != '\\' {
			continue
		}
		index++
		if index >= len(data) {
			return false
		}
		if data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return false
		}
		value, ok := hexCode(data[index+1 : index+5])
		if !ok {
			return false
		}
		index += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			low, ok := hexCode(data[index+3 : index+7])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return true // Remaining JSON syntax is validated by the decoder.
}

func hexCode(data []byte) (uint16, bool) {
	var value uint16
	for _, digit := range data {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit - 'a' + 10)
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit - 'A' + 10)
		default:
			return 0, false
		}
	}
	return value, true
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, digit := range value {
		if !(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

// ValidateMetadata also checks the claimed content fingerprint. It does not
// sort, normalize paths, trim identity fields or verify payload contents.
func ValidateMetadata(metadata Metadata, limits Limits) error {
	if err := validateFields(metadata, limits); err != nil {
		return err
	}
	if !validSHA256(metadata.ContentDigest) {
		return fmt.Errorf("%w: content_digest", ErrInvalidMetadata)
	}
	if contentDigest(metadata) != metadata.ContentDigest {
		return ErrDigestMismatch
	}
	return nil
}

func validateFields(metadata Metadata, limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if metadata.Format != Format || metadata.FormatVersion != FormatVersion || metadata.Profile != Profile {
		return fmt.Errorf("%w: format/version/profile", ErrInvalidMetadata)
	}
	if !validIdentity(metadata.HostID) || !validIdentity(metadata.Version) || !validIdentity(metadata.CaseName) {
		return fmt.Errorf("%w: identity/display name", ErrInvalidMetadata)
	}
	if len(metadata.Files) == 0 {
		return fmt.Errorf("%w: non-empty inventory required", ErrInvalidMetadata)
	}
	if len(metadata.Files) > limits.FileCount {
		return fmt.Errorf("%w: file count", ErrLimitExceeded)
	}
	prefixes := map[string]string{}
	files := map[string]bool{}
	var total int64
	manifestFound := false
	for index, file := range metadata.Files {
		if err := ValidatePayloadPath(file.Path); err != nil {
			return err
		}
		if index > 0 && metadata.Files[index-1].Path >= file.Path {
			return fmt.Errorf("%w: inventory must be strictly sorted", ErrInvalidMetadata)
		}
		if file.Size < 0 || !validSHA256(file.SHA256) {
			return fmt.Errorf("%w: file size/hash", ErrInvalidMetadata)
		}
		if file.Size > limits.FileBytes || file.Size > limits.PayloadBytes-total {
			return fmt.Errorf("%w: file/payload bytes", ErrLimitExceeded)
		}
		total += file.Size
		components := strings.Split(file.Path, "/")
		for position := range components {
			prefix := strings.Join(components[:position+1], "/")
			folded := strings.ToLower(prefix) // Paths have already been limited to ASCII.
			if original, ok := prefixes[folded]; ok && original != prefix {
				return fmt.Errorf("%w: case-folded path alias", ErrInvalidPath)
			}
			if position < len(components)-1 && files[folded] {
				return fmt.Errorf("%w: file is a directory prefix", ErrInvalidPath)
			}
			if position == len(components)-1 {
				if _, isDirectory := prefixes[folded]; isDirectory && !files[folded] {
					return fmt.Errorf("%w: directory is a file", ErrInvalidPath)
				}
				if files[folded] {
					return fmt.Errorf("%w: duplicate path", ErrInvalidPath)
				}
				files[folded] = true
			}
			prefixes[folded] = prefix
		}
		if file.Path == "manifest.json" {
			manifestFound = true
		}
	}
	if !manifestFound {
		return fmt.Errorf("%w: manifest.json required", ErrInvalidMetadata)
	}
	return nil
}

// ContentDigest computes the v1 fingerprint from validated declarations. The
// previous ContentDigest field is ignored to support creation of a descriptor.
func ContentDigest(metadata Metadata, limits Limits) (string, error) {
	if err := validateFields(metadata, limits); err != nil {
		return "", err
	}
	return contentDigest(metadata), nil
}

func contentDigest(metadata Metadata) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "IR-Toolkit-Case-Package-v1\x00")
	lengthPrefixed := func(value string) {
		_ = binary.Write(hash, binary.BigEndian, uint32(len(value)))
		_, _ = io.WriteString(hash, value)
	}
	for _, value := range []string{metadata.Profile, metadata.HostID, metadata.Version, metadata.CaseName} {
		lengthPrefixed(value)
	}
	_ = binary.Write(hash, binary.BigEndian, uint32(len(metadata.Files)))
	for _, file := range metadata.Files {
		lengthPrefixed(file.Path)
		_ = binary.Write(hash, binary.BigEndian, uint64(file.Size))
		decoded, _ := hex.DecodeString(file.SHA256)
		_, _ = hash.Write(decoded)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
