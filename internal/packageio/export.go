package packageio

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrSourceChanged = errors.New("case source changed during export")

// ExportCase exports all regular files from a trusted, stopped case directory.
// caseName is display-only; identity is derived from unchanged source JSON.
// Symlinks, in-tree hard-link aliases and special files are rejected. It does
// not load investigation domains.
// The caller owns writer and must discard all output on failure, including a
// seemingly complete archive: streaming writes cannot be rolled back here.
// writer must be outside the source tree; publishing a new output file safely
// is the responsibility of the caller/CLI assembly layer.
func ExportCase(ctx context.Context, directory, caseName string, writer io.Writer, limits Limits) (ContainerVerification, error) {
	if err := limits.validate(); err != nil {
		return ContainerVerification{}, err
	}
	if ctx == nil || writer == nil || directory == "" {
		return ContainerVerification{}, fmt.Errorf("%w: context, source directory and writer required", ErrInvalidSource)
	}
	if !validIdentity(caseName) {
		return ContainerVerification{}, fmt.Errorf("%w: display name", ErrInvalidMetadata)
	}
	root, err := filepath.Abs(directory)
	if err != nil {
		return ContainerVerification{}, err
	}
	nodes, err := scanSource(ctx, root, limits)
	if err != nil {
		return ContainerVerification{}, err
	}
	metadata := Metadata{Format: Format, FormatVersion: FormatVersion, Profile: Profile, CaseName: caseName}
	selected := map[string]*bytes.Buffer{}
	var files []sourceNode
	for _, node := range nodes {
		if !node.info.Mode().IsRegular() {
			continue
		}
		files = append(files, node)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	// Reuse one operation-local buffer across both passes, never across exports.
	copyBuffer := make([]byte, 32<<10)
	for _, node := range files {
		var capture io.Writer = io.Discard
		if node.path == "manifest.json" || node.path == "host/host.json" {
			if node.info.Size() > limits.MetadataBytes {
				return ContainerVerification{}, fmt.Errorf("%w: source JSON %q", ErrLimitExceeded, node.path)
			}
			buffer := new(bytes.Buffer)
			selected[node.path] = buffer
			capture = buffer
		}
		hash, err := copySource(ctx, root, node, capture, copyBuffer)
		if err != nil {
			return ContainerVerification{}, err
		}
		metadata.Files = append(metadata.Files, File{Path: node.path, Size: node.info.Size(), SHA256: hash})
	}
	hostID, version, manifest, err := sourceIdentity(selected)
	if err != nil {
		return ContainerVerification{}, err
	}
	metadata.HostID, metadata.Version = hostID, version
	metadata.ContentDigest, err = ContentDigest(metadata, limits)
	if err != nil {
		return ContainerVerification{}, err
	}
	if err := verifyReferences(manifest["files"], metadata.Files, limits); err != nil {
		return ContainerVerification{}, err
	}
	descriptor, err := json.Marshal(metadata)
	if err != nil {
		return ContainerVerification{}, err
	}
	if int64(len(descriptor)) > limits.MetadataBytes {
		return ContainerVerification{}, fmt.Errorf("%w: descriptor bytes", ErrLimitExceeded)
	}
	// Preflight the entire output size before the first write. Fixed USTAR
	// framing has one header per entry and exactly two terminator blocks.
	expected := int64(2*tarBlockSize) + entryBytes(int64(len(descriptor)))
	var payload int64
	for _, file := range metadata.Files {
		expected += entryBytes(file.Size)
		payload += file.Size
	}
	if expected > limits.ContainerBytes {
		return ContainerVerification{}, fmt.Errorf("%w: exported container bytes", ErrLimitExceeded)
	}
	output := &exportOutput{ctx: ctx, writer: writer, maximum: limits.ContainerBytes}
	archive := tar.NewWriter(output)
	if err := writeExportHeader(archive, "package.json", int64(len(descriptor))); err != nil {
		return ContainerVerification{}, err
	}
	if _, err := archive.Write(descriptor); err != nil {
		return ContainerVerification{}, err
	}
	for index, node := range files {
		if err := writeExportHeader(archive, "case/"+node.path, node.info.Size()); err != nil {
			return ContainerVerification{}, err
		}
		hash, err := copySource(ctx, root, node, archive, copyBuffer)
		if err != nil {
			return ContainerVerification{}, err
		}
		if hash != metadata.Files[index].SHA256 {
			return ContainerVerification{}, fmt.Errorf("%w: hash for %q", ErrSourceChanged, node.path)
		}
	}
	current, err := scanSource(ctx, root, limits)
	if err != nil {
		return ContainerVerification{}, err
	}
	if len(nodes) != len(current) {
		return ContainerVerification{}, ErrSourceChanged
	}
	for index, node := range nodes {
		if node.path != current[index].path || !sameSourceInfo(node.info, current[index].info) {
			return ContainerVerification{}, ErrSourceChanged
		}
	}
	if err := archive.Close(); err != nil {
		return ContainerVerification{}, err
	}
	if err := ctx.Err(); err != nil {
		return ContainerVerification{}, err
	}
	if output.count != expected {
		return ContainerVerification{}, ErrInvalidContainer
	}
	return ContainerVerification{Metadata: metadata, PayloadBytes: payload, ContainerBytes: output.count}, nil
}

type sourceNode struct {
	path string
	info fs.FileInfo
}

func scanSource(ctx context.Context, root string, limits Limits) ([]sourceNode, error) {
	var nodes []sourceNode
	aliases := map[string]string{}
	var identities sourceIdentityIndex
	var fileCount int
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if path == root {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: source root must be a real directory", ErrInvalidSource)
			}
		} else {
			if err := ValidatePayloadPath(relative); err != nil {
				return err
			}
			folded := strings.ToLower(relative)
			if original, exists := aliases[folded]; exists && original != relative {
				return fmt.Errorf("%w: source path alias", ErrInvalidPath)
			}
			aliases[folded] = relative
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%w: links/special files forbidden: %q", ErrInvalidSource, relative)
		}
		if info.Mode().IsRegular() {
			fileCount++
			if fileCount > limits.FileCount || info.Size() < 0 || info.Size() > limits.FileBytes || info.Size() > limits.PayloadBytes-total {
				return fmt.Errorf("%w: source files/bytes", ErrLimitExceeded)
			}
			total += info.Size()
			if identities.add(info) {
				return fmt.Errorf("%w: hard-linked source paths", ErrInvalidSource)
			}
		}
		// Empty directory trees are not payload but must not grow without bound.
		if len(nodes) >= limits.FileCount*8+1 {
			return fmt.Errorf("%w: source tree entries", ErrLimitExceeded)
		}
		nodes = append(nodes, sourceNode{path: relative, info: info})
		return nil
	})
	return nodes, err
}

func sameSourceInfo(before, after fs.FileInfo) bool {
	if !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return false
	}
	// Directory mtimes are not portable; the final walk checks their entries.
	return before.IsDir() || (before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()))
}

func copySource(ctx context.Context, root string, node sourceNode, writer io.Writer, buffer []byte) (string, error) {
	file, err := os.Open(filepath.Join(root, filepath.FromSlash(node.path)))
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !sameSourceInfo(node.info, info) {
		return "", fmt.Errorf("%w: %q", ErrSourceChanged, node.path)
	}
	hash := sha256.New()
	input := &containerInput{ctx: ctx, reader: file, maximum: node.info.Size()}
	count, err := io.CopyBuffer(io.MultiWriter(writer, hash), input, buffer)
	if err != nil {
		return "", fmt.Errorf("copy source %q: %w", node.path, err)
	}
	info, err = file.Stat()
	if err != nil {
		return "", err
	}
	if count != node.info.Size() || !sameSourceInfo(node.info, info) {
		return "", fmt.Errorf("%w: %q", ErrSourceChanged, node.path)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func entryBytes(size int64) int64 {
	return tarBlockSize + size + (tarBlockSize-size%tarBlockSize)%tarBlockSize
}

func writeExportHeader(writer *tar.Writer, name string, size int64) error {
	return writer.WriteHeader(&tar.Header{Name: name, Size: size, Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR, ModTime: time.Unix(0, 0)})
}

type exportOutput struct {
	ctx            context.Context
	writer         io.Writer
	maximum, count int64
}

func (w *exportOutput) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(data)) > w.maximum-w.count {
		return 0, ErrLimitExceeded
	}
	count, err := w.writer.Write(data)
	w.count += int64(count)
	if err == nil && count != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = w.ctx.Err()
	}
	return count, err
}
