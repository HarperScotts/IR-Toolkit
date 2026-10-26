package packageio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	ErrInvalidSource     = errors.New("invalid package source JSON")
	ErrManifestReference = errors.New("manifest reference does not match package inventory")
	ErrSourceIdentity    = errors.New("source identity does not match package metadata")
)

// VerifySource verifies the container, manifest evidence references and effective
// Local host/version identity. It does not load domains or authenticate a sender.
// Only manifest.json and host/host.json are retained temporarily, each bounded by
// MetadataBytes (in addition to the descriptor budget). No filesystem writes occur.
func VerifySource(ctx context.Context, reader io.Reader, limits Limits) (ContainerVerification, error) {
	return verifySource(ctx, reader, limits, nil)
}

// capture remains private; extracted bytes are not exposed until all checks pass.
func verifySource(ctx context.Context, reader io.Reader, limits Limits, capture func(File) (io.Writer, error)) (ContainerVerification, error) {
	selected := map[string]*bytes.Buffer{}
	verified, err := verifyContainer(ctx, reader, limits, func(file File) (io.Writer, error) {
		var buffer *bytes.Buffer
		if file.Path == "manifest.json" || file.Path == "host/host.json" {
			if file.Size > limits.MetadataBytes {
				return nil, fmt.Errorf("%w: source JSON %q", ErrLimitExceeded, file.Path)
			}
			buffer = new(bytes.Buffer)
			selected[file.Path] = buffer
		}
		if capture != nil {
			writer, err := capture(file)
			if err != nil {
				return nil, err
			}
			if writer != nil {
				if buffer == nil {
					return writer, nil
				}
				closer, _ := writer.(io.Closer)
				return &sourceCapture{Writer: io.MultiWriter(writer, buffer), closer: closer}, nil
			}
		}
		if buffer == nil {
			return nil, nil
		}
		return buffer, nil
	})
	if err != nil {
		return ContainerVerification{}, err
	}
	hostID, version, manifest, err := sourceIdentity(selected)
	if err != nil {
		return ContainerVerification{}, err
	}
	if hostID != verified.Metadata.HostID || version != verified.Metadata.Version {
		return ContainerVerification{}, ErrSourceIdentity
	}
	if err := verifyReferences(manifest["files"], verified.Metadata.Files, limits); err != nil {
		return ContainerVerification{}, err
	}
	if err := ctx.Err(); err != nil {
		return ContainerVerification{}, err
	}
	return verified, nil
}

type sourceCapture struct {
	io.Writer
	closer io.Closer
}

func (w *sourceCapture) Close() error {
	if w.closer != nil {
		return w.closer.Close()
	}
	return nil
}

func sourceIdentity(selected map[string]*bytes.Buffer) (string, string, map[string]json.RawMessage, error) {
	manifest, err := sourceObject(selectedBytes(selected, "manifest.json"))
	if err != nil {
		return "", "", nil, fmt.Errorf("manifest: %w", err)
	}
	host, err := sourceObject(selectedBytes(selected, "host/host.json"))
	if err != nil {
		return "", "", nil, fmt.Errorf("host: %w", err)
	}
	version, err := sourceString(manifest, "case_id", true)
	if err != nil {
		return "", "", nil, err
	}
	hostID, err := sourceString(host, "hostname", false)
	if err != nil {
		return "", "", nil, err
	}
	manifestHost, err := sourceString(manifest, "hostname", false)
	if err != nil {
		return "", "", nil, err
	}
	if hostID == "" {
		hostID = manifestHost
	}
	return hostID, version, manifest, nil
}

func selectedBytes(selected map[string]*bytes.Buffer, name string) []byte {
	if buffer := selected[name]; buffer != nil {
		return buffer.Bytes()
	}
	return nil
}

// Ancillary fields are preserved as opaque JSON for forward compatibility.
// Identity keys are exact; reject all top-level case-fold aliases/duplicates so
// encoding/json's case-insensitive struct matching cannot change interpretation.
func sourceObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) || !validJSONEscapes(data) {
		return nil, ErrInvalidSource
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrInvalidSource
	}
	fields := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidSource
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrInvalidSource
		}
		folded := foldSourceKey(key)
		if seen[folded] {
			return nil, fmt.Errorf("%w: duplicate/aliased field %q", ErrInvalidSource, key)
		}
		seen[folded] = true
		for _, identityKey := range []string{"hostname", "case_id", "files"} {
			if key != identityKey && strings.EqualFold(key, identityKey) {
				return nil, fmt.Errorf("%w: noncanonical field %q", ErrInvalidSource, key)
			}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrInvalidSource
		}
		fields[key] = raw
	}
	if _, err := decoder.Token(); err != nil {
		return nil, ErrInvalidSource
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, ErrInvalidSource
	}
	return fields, nil
}

func foldSourceKey(key string) string {
	return strings.Map(func(value rune) rune {
		minimum := value
		for next := unicode.SimpleFold(value); next != value; next = unicode.SimpleFold(next) {
			if next < minimum {
				minimum = next
			}
		}
		return minimum
	}, key)
}

func sourceString(fields map[string]json.RawMessage, key string, required bool) (string, error) {
	raw, exists := fields[key]
	if !exists && !required {
		return "", nil
	}
	var value string
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
		return "", fmt.Errorf("%w: string %s required", ErrInvalidSource, key)
	}
	return strings.TrimSpace(value), nil
}

func verifyReferences(raw json.RawMessage, inventory []File, limits Limits) error {
	// Existing Manifest serializes a nil Files slice as null. Missing/null/empty
	// lists all mean no references, never completeness or authenticity.
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return ErrInvalidSource
	}
	available := map[string]File{}
	for _, file := range inventory {
		available[file.Path] = file
	}
	seen := map[string]bool{}
	for decoder.More() {
		if len(seen) >= limits.FileCount {
			return ErrLimitExceeded
		}
		var entry json.RawMessage
		if err := decoder.Decode(&entry); err != nil {
			return ErrInvalidSource
		}
		fields, err := readObject(entry, []string{"path", "size", "sha256"})
		if err != nil {
			return fmt.Errorf("%w: reference: %v", ErrInvalidSource, err)
		}
		var file File
		if json.Unmarshal(fields["path"], &file.Path) != nil || json.Unmarshal(fields["size"], &file.Size) != nil || json.Unmarshal(fields["sha256"], &file.SHA256) != nil {
			return ErrInvalidSource
		}
		if err := ValidatePayloadPath(file.Path); err != nil {
			return err
		}
		if seen[file.Path] || available[file.Path] != file {
			return fmt.Errorf("%w: %q", ErrManifestReference, file.Path)
		}
		seen[file.Path] = true
	}
	if _, err := decoder.Token(); err != nil {
		return ErrInvalidSource
	}
	return nil
}
