package packageio

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidContainer = errors.New("invalid package container")
	ErrPayloadMismatch  = errors.New("package payload does not match inventory")
)

const tarBlockSize = 512
const maxTailBytes = 10 << 10

// ContainerVerification confirms framing and actual payload hashes only, not
// manifest references, domain loadability, sender identity or committed state.
type ContainerVerification struct {
	Metadata       Metadata
	PayloadBytes   int64
	ContainerBytes int64
}

// VerifyContainer reads one restricted, uncompressed USTAR stream without any
// filesystem writes or retention of payload contents. No partial result is
// returned on failure. Cancellation is checked between reads; a blocking input
// Reader must provide its own deadline/close mechanism.
func VerifyContainer(ctx context.Context, reader io.Reader, limits Limits) (ContainerVerification, error) {
	return verifyContainer(ctx, reader, limits, nil)
}

// capture is private: callers never receive unverified payload bytes.
func verifyContainer(ctx context.Context, reader io.Reader, limits Limits, capture func(File) (io.Writer, error)) (ContainerVerification, error) {
	if err := limits.validate(); err != nil {
		return ContainerVerification{}, err
	}
	if ctx == nil || reader == nil {
		return ContainerVerification{}, fmt.Errorf("%w: context and reader required", ErrInvalidContainer)
	}
	input := &containerInput{ctx: ctx, reader: reader, maximum: limits.ContainerBytes}
	header, err := readRegularHeader(input)
	if err != nil {
		return ContainerVerification{}, err
	}
	if header.Name != "package.json" {
		return ContainerVerification{}, fmt.Errorf("%w: first entry must be package.json", ErrInvalidContainer)
	}
	if header.Size > limits.MetadataBytes {
		return ContainerVerification{}, fmt.Errorf("%w: descriptor header size", ErrLimitExceeded)
	}
	descriptor := &io.LimitedReader{R: input, N: header.Size}
	metadata, err := ReadMetadata(descriptor, limits)
	if err != nil {
		return ContainerVerification{}, err
	}
	if descriptor.N != 0 {
		return ContainerVerification{}, fmt.Errorf("%w: truncated descriptor", ErrInvalidContainer)
	}
	if err := readPadding(input, header.Size); err != nil {
		return ContainerVerification{}, err
	}
	var actualPayload int64
	buffer := make([]byte, 32<<10)
	for _, file := range metadata.Files {
		header, err := readRegularHeader(input)
		if err != nil {
			return ContainerVerification{}, err
		}
		if !strings.HasPrefix(header.Name, "case/") {
			return ContainerVerification{}, fmt.Errorf("%w: payload outside case/", ErrInvalidPath)
		}
		if err := ValidatePayloadPath(strings.TrimPrefix(header.Name, "case/")); err != nil {
			return ContainerVerification{}, err
		}
		if header.Size > limits.FileBytes || header.Size > limits.PayloadBytes-actualPayload {
			return ContainerVerification{}, fmt.Errorf("%w: payload header size", ErrLimitExceeded)
		}
		if header.Name != "case/"+file.Path || header.Size != file.Size {
			return ContainerVerification{}, fmt.Errorf("%w: entry name/size for %q", ErrPayloadMismatch, file.Path)
		}
		hash := sha256.New()
		var destination io.Writer = hash
		var closer io.Closer
		if capture != nil {
			writer, err := capture(file)
			if err != nil {
				return ContainerVerification{}, err
			}
			if writer != nil {
				destination = io.MultiWriter(hash, writer)
				closer, _ = writer.(io.Closer)
			}
		}
		count, err := io.CopyBuffer(destination, io.LimitReader(input, header.Size), buffer)
		if closer != nil {
			err = errors.Join(err, closer.Close())
		}
		if err != nil {
			return ContainerVerification{}, fmt.Errorf("read payload %q: %w", file.Path, err)
		}
		if count != header.Size {
			return ContainerVerification{}, fmt.Errorf("%w: truncated payload %q: %w", ErrInvalidContainer, file.Path, io.ErrUnexpectedEOF)
		}
		actualPayload += count // Declarations were checked against the bounded total.
		if hex.EncodeToString(hash.Sum(nil)) != file.SHA256 {
			return ContainerVerification{}, fmt.Errorf("%w: SHA-256 for %q", ErrPayloadMismatch, file.Path)
		}
		if err := readPadding(input, header.Size); err != nil {
			return ContainerVerification{}, err
		}
	}
	for range 2 {
		block, err := readBlock(input)
		if err != nil {
			return ContainerVerification{}, err
		}
		if !allZero(block[:]) {
			return ContainerVerification{}, fmt.Errorf("%w: expected two zero end blocks; extra entry/data", ErrInvalidContainer)
		}
	}
	// A standard tar.Reader stops at its terminator; explicitly inspect the rest
	// so concatenated archives and non-zero trailing data cannot be ignored.
	for tail := 0; ; tail += tarBlockSize {
		var block [tarBlockSize]byte
		count, err := io.ReadFull(input, block[:])
		if count == 0 && err == io.EOF {
			break
		}
		if err != nil {
			return ContainerVerification{}, fmt.Errorf("%w: trailing block: %w", ErrInvalidContainer, err)
		}
		if tail >= maxTailBytes {
			return ContainerVerification{}, fmt.Errorf("%w: trailing zero blocks", ErrLimitExceeded)
		}
		if !allZero(block[:]) {
			return ContainerVerification{}, fmt.Errorf("%w: non-zero trailing data", ErrInvalidContainer)
		}
	}
	if err := ctx.Err(); err != nil {
		return ContainerVerification{}, err
	}
	return ContainerVerification{Metadata: metadata, PayloadBytes: actualPayload, ContainerBytes: input.count}, nil
}

type containerInput struct {
	ctx        context.Context
	reader     io.Reader
	maximum    int64
	count      int64
	pending    error
	emptyReads int
}

func (r *containerInput) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.pending != nil {
		return 0, r.pending
	}
	// Permit exactly one probe byte beyond the limit to distinguish EOF at an
	// exact budget from a stream with additional data. Never read further.
	remaining := r.maximum - r.count
	if remaining < 0 {
		return 0, ErrLimitExceeded
	}
	if int64(len(data)) > remaining+1 {
		data = data[:int(remaining+1)]
	}
	count, err := r.reader.Read(data)
	if count == 0 && err == nil {
		r.emptyReads++
		if r.emptyReads >= 100 {
			return 0, io.ErrNoProgress
		}
	} else {
		r.emptyReads = 0
	}
	// io.ReadFull may discard an error returned alongside a complete block.
	// Remember it so the next boundary/probe cannot turn an IO failure into success.
	if count > 0 && err != nil {
		r.pending = err
	}
	r.count += int64(count)
	if r.count > r.maximum {
		r.pending = fmt.Errorf("%w: container bytes", ErrLimitExceeded)
		return count, r.pending
	}
	if cancelled := r.ctx.Err(); cancelled != nil {
		return count, cancelled
	}
	return count, err
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func readBlock(reader io.Reader) ([tarBlockSize]byte, error) {
	var block [tarBlockSize]byte
	if _, err := io.ReadFull(reader, block[:]); err != nil {
		return block, fmt.Errorf("%w: incomplete block: %w", ErrInvalidContainer, err)
	}
	return block, nil
}

func readPadding(reader io.Reader, size int64) error {
	padding := (tarBlockSize - size%tarBlockSize) % tarBlockSize
	var block [tarBlockSize]byte
	if _, err := io.ReadFull(reader, block[:int(padding)]); err != nil {
		return fmt.Errorf("%w: incomplete padding: %w", ErrInvalidContainer, err)
	}
	if !allZero(block[:int(padding)]) {
		return fmt.Errorf("%w: non-zero file padding", ErrInvalidContainer)
	}
	return nil
}

// Reject hidden extensions before a standard Reader has an opportunity to
// consume them. Paths fit in the 100-byte name field, so v1 needs no prefix.
// tar.Reader is then given only this fixed block to validate checksum/numbers.
func readRegularHeader(reader io.Reader) (*tar.Header, error) {
	block, err := readBlock(reader)
	if err != nil {
		return nil, err
	}
	invalid := func(reason string) (*tar.Header, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidContainer, reason)
	}
	if !bytes.Equal(block[257:263], []byte("ustar\x00")) || !bytes.Equal(block[263:265], []byte("00")) {
		return invalid("USTAR header required")
	}
	if block[156] != tar.TypeReg {
		return invalid("only raw regular-file headers are allowed")
	}
	if !allZero(block[157:257]) || !allZero(block[345:512]) {
		return invalid("links, prefix and extended header fields are forbidden")
	}
	nameBytes := block[:100]
	if terminator := bytes.IndexByte(nameBytes, 0); terminator >= 0 {
		if !allZero(nameBytes[terminator:]) {
			return invalid("hidden bytes after name terminator")
		}
		nameBytes = nameBytes[:terminator]
	}
	name := string(nameBytes)
	if name != "package.json" {
		if !strings.HasPrefix(name, "case/") {
			return nil, fmt.Errorf("%w: entry outside case/", ErrInvalidPath)
		}
		if err := ValidatePayloadPath(strings.TrimPrefix(name, "case/")); err != nil {
			return nil, err
		}
	}
	// Canonical v1 sizes are unsigned ASCII octal, never base-256 or signed.
	sizeField := bytes.Trim(block[124:136], " \x00")
	if len(sizeField) == 0 {
		return invalid("missing octal size")
	}
	for _, digit := range sizeField {
		if digit < '0' || digit > '7' {
			return invalid("non-octal size")
		}
	}
	header, err := tar.NewReader(bytes.NewReader(block[:])).Next()
	if err != nil {
		return nil, fmt.Errorf("%w: header validation: %w", ErrInvalidContainer, err)
	}
	if header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || header.Name != name || header.Size < 0 {
		return invalid("unsupported header interpretation")
	}
	return header, nil
}
