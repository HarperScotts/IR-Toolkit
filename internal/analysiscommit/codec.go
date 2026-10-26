package analysiscommit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

type shape struct {
	kind     byte
	nullable bool
	fields   map[string]*shape
	item     *shape
}

var (
	textShape   = &shape{kind: 's'}
	numberShape = &shape{kind: 'n'}
	boundShape  = &shape{kind: 's', nullable: true}
	fileFields  = map[string]*shape{"path": textShape, "size": numberShape, "sha256": textShape}
	fileShape   = &shape{kind: '{', fields: fileFields}
	iocShape    = &shape{kind: '{', nullable: true, fields: fileFields}
	listShape   = &shape{kind: '[', item: fileShape}
	runShape    = &shape{kind: '{', fields: map[string]*shape{"format": textShape, "format_version": numberShape, "run_id": textShape}}
	commitShape = &shape{kind: '{', fields: map[string]*shape{
		"format": textShape, "format_version": numberShape, "run_id": textShape,
		"tool_version": textShape, "rules_version": textShape, "host_id": textShape, "collection_id": textShape,
		"window": {kind: '{', fields: map[string]*shape{"since": boundShape, "until": boundShape}},
		"inputs": listShape, "ioc": iocShape, "files": listShape, "content_digest": textShape,
	}}
)

func checkShape(decoder *json.Decoder, expected *shape, maximum int) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: JSON token: %v", ErrInvalid, err)
	}
	if token == nil && expected.nullable {
		return nil
	}
	switch expected.kind {
	case 's':
		if _, ok := token.(string); !ok {
			return ErrInvalid
		}
	case 'n':
		n, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		if _, err := n.Int64(); err != nil {
			return ErrInvalid
		}
	case '{':
		if token != json.Delim('{') {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return ErrInvalid
			}
			key, ok := token.(string)
			child, exists := expected.fields[key]
			if !ok || !exists || seen[key] {
				return fmt.Errorf("%w: duplicate/unknown field %q", ErrInvalid, key)
			}
			seen[key] = true
			if err := checkShape(decoder, child, maximum); err != nil {
				return err
			}
		}
		if len(seen) != len(expected.fields) {
			return fmt.Errorf("%w: missing field", ErrInvalid)
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		if token != json.Delim('[') {
			return ErrInvalid
		}
		count := 0
		for decoder.More() {
			if count >= maximum {
				return ErrLimit
			}
			if err := checkShape(decoder, expected.item, maximum); err != nil {
				return err
			}
			count++
		}
		if token, err = decoder.Token(); err != nil || token != json.Delim(']') {
			return ErrInvalid
		}
	}
	return nil
}

// Reject unpaired escaped surrogates before encoding/json replaces them. Other
// JSON syntax, including escape spelling, is checked by the strict shape walk.
func validEscapes(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func readStrict(reader io.Reader, limits Limits, expected *shape, target any) ([]byte, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(reader, limits.MetadataBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read completion metadata: %w", err)
	}
	if int64(len(data)) > limits.MetadataBytes {
		return nil, ErrLimit
	}
	if !utf8.Valid(data) || !validEscapes(data) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := checkShape(decoder, expected, limits.FileCount); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return nil, fmt.Errorf("%w: typed field: %v", ErrInvalid, err)
	}
	return data, nil
}

func wireSize(data []byte, files []File, limits Limits) error {
	size := int64(len(data))
	if size > limits.MetadataBytes || size > limits.FileBytes || size > limits.PayloadBytes {
		return ErrLimit
	}
	for _, file := range files {
		if file.Size > limits.PayloadBytes-size {
			return ErrLimit
		}
		size += file.Size
	}
	return nil
}

func ReadRun(reader io.Reader, limits Limits) (Run, error) {
	var run Run
	data, err := readStrict(reader, limits, runShape, &run)
	if err == nil {
		err = ValidateRun(run)
	}
	if err == nil {
		err = wireSize(data, nil, limits)
	}
	if err != nil {
		return Run{}, err
	}
	return run, nil
}

func ReadCommit(reader io.Reader, limits Limits) (Commit, error) {
	var commit Commit
	data, err := readStrict(reader, limits, commitShape, &commit)
	if err == nil {
		err = Validate(commit, limits)
	}
	if err == nil {
		err = wireSize(data, commit.Files, limits)
	}
	if err != nil {
		return Commit{}, err
	}
	return commit, nil
}

func EncodeRun(run Run, limits Limits) ([]byte, error) {
	if err := limits.validate(); err != nil {
		return nil, err
	}
	if err := ValidateRun(run); err != nil {
		return nil, err
	}
	data, err := json.Marshal(run)
	if err != nil {
		return nil, err
	}
	if err := wireSize(data, nil, limits); err != nil {
		return nil, err
	}
	return data, nil
}

// EncodeCommit requires an existing valid digest; it never silently repairs it.
func EncodeCommit(commit Commit, limits Limits) ([]byte, error) {
	if err := Validate(commit, limits); err != nil {
		return nil, err
	}
	data, err := json.Marshal(commit)
	if err != nil {
		return nil, err
	}
	if err := wireSize(data, commit.Files, limits); err != nil {
		return nil, err
	}
	return data, nil
}
