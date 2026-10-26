package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"ir-toolkit/internal/packageio"
)

func TestCasePackageCommandsRoundTrip(t *testing.T) {
	source := archiveFixtureSource(t, "alpha", "collection-1").Dir
	before := readPackageTree(t, source)
	parent := t.TempDir()
	path := filepath.Join(parent, "case.ircase.tar")
	var output bytes.Buffer
	pack := newCasePackCommand()
	pack.SetOut(&output)
	pack.SetArgs([]string{source, "--output", path})
	if err := pack.Execute(); err != nil {
		t.Fatal(err)
	}
	var packed packageReceipt
	if err := json.Unmarshal(output.Bytes(), &packed); err != nil {
		t.Fatal(err)
	}
	if packed.Status != "exported" || !packed.DomainsLoaded || packed.Committed || packed.HostID != "alpha" || packed.Version != "collection-1" || packed.CaseName != filepath.Base(source) || packed.FileCount != len(before) {
		t.Fatalf("receipt: %+v", packed)
	}
	if !reflect.DeepEqual(before, readPackageTree(t, source)) {
		t.Fatal("pack changed source evidence")
	}
	packageBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	output.Reset()
	verify := newCaseVerifyCommand()
	verify.SetOut(&output)
	verify.SetArgs([]string{path})
	if err := verify.Execute(); err != nil {
		t.Fatal(err)
	}
	var verified packageReceipt
	if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
		t.Fatal(err)
	}
	if verified.Status != "verified-framing-source" || verified.DomainsLoaded || verified.Committed || verified.ContentDigest != packed.ContentDigest || verified.ContainerBytes != int64(len(packageBytes)) {
		t.Fatalf("verify receipt: %+v", verified)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, packageBytes) {
		t.Fatal("verify changed package")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != "case.ircase.tar" {
		t.Fatalf("verify wrote temporary/repository data: %v %v", entries, err)
	}
	for _, name := range []string{"case-pack", "case-verify"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil || cmd.Name() != name {
			t.Fatalf("command not registered: %s %v", name, err)
		}
	}
}

func readPackageTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCasePackDoesNotOverwriteOrWriteInsideSource(t *testing.T) {
	source := writeCentralCaseFixture(t, "alpha", "1")
	parent := t.TempDir()
	existing := filepath.Join(parent, "existing.tar")
	if err := os.WriteFile(existing, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := packCaseFile(context.Background(), source, existing); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing file: %v", err)
	}
	bytes, err := os.ReadFile(existing)
	if err != nil || string(bytes) != "keep" {
		t.Fatal("existing output was altered")
	}
	before := readPackageTree(t, source)
	inside := filepath.Join(source, "new.tar")
	if _, err := packCaseFile(context.Background(), source, inside); err == nil {
		t.Fatal("output inside source accepted")
	}
	alias := filepath.Join(parent, "source-alias")
	if err := os.Symlink(source, alias); err == nil {
		if _, err := packCaseFile(context.Background(), source, filepath.Join(alias, "new.tar")); err == nil {
			t.Fatal("symlink output parent bypassed containment")
		}
	}
	if !reflect.DeepEqual(before, readPackageTree(t, source)) {
		t.Fatal("rejected output modified source")
	}
	link := filepath.Join(parent, "output-link")
	if err := os.Symlink(existing, link); err == nil {
		if _, err := packCaseFile(context.Background(), source, link); !errors.Is(err, os.ErrExist) {
			t.Fatalf("existing symlink: %v", err)
		}
		info, err := os.Lstat(link)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("existing symlink removed")
		}
	}
	if _, err := packCaseFile(context.Background(), source, filepath.Join(parent, "missing-parent", "new.tar")); err == nil {
		t.Fatal("missing output parent accepted")
	}
}

func TestCasePackFailureCleansOnlyNewOutput(t *testing.T) {
	for _, kind := range []string{"broken domain", "missing domain", "invalid source JSON", "invalid filename"} {
		t.Run(kind, func(t *testing.T) {
			source := writeCentralCaseFixture(t, "alpha", "1")
			switch kind {
			case "broken domain":
				if err := os.WriteFile(filepath.Join(source, "process/processes.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing domain":
				if err := os.Remove(filepath.Join(source, "process/processes.json")); err != nil {
					t.Fatal(err)
				}
			case "invalid source JSON":
				if err := os.WriteFile(filepath.Join(source, "host/host.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "invalid filename":
				if err := os.WriteFile(filepath.Join(source, "unsafe name.json"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readPackageTree(t, source)
			parent := t.TempDir()
			path := filepath.Join(parent, "new.tar")
			result, err := packCaseFile(context.Background(), source, path)
			if err == nil || result.ContainerBytes != 0 {
				t.Fatalf("invalid case exported: %+v %v", result, err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("incomplete output retained: %v", err)
			}
			if !reflect.DeepEqual(before, readPackageTree(t, source)) {
				t.Fatal("cleanup changed source")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("leftover output: %v %v", entries, err)
			}
		})
	}
}

func TestCaseVerifyDoesNotClaimDomainLoadability(t *testing.T) {
	source := writeCentralCaseFixture(t, "alpha", "1")
	if err := os.WriteFile(filepath.Join(source, "process/processes.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	var data bytes.Buffer
	if _, err := packageio.ExportCase(context.Background(), source, "case", &data, packageio.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "valid-framing.tar")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCaseFile(context.Background(), path); err != nil {
		t.Fatalf("read-only verify unexpectedly loaded domains: %v", err)
	}
	if err := os.WriteFile(path, append(data.Bytes(), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCaseFile(context.Background(), path); !errors.Is(err, packageio.ErrInvalidContainer) {
		t.Fatalf("bad tail: %v", err)
	}
}

func TestCasePackageCancellationAndArguments(t *testing.T) {
	source := writeCentralCaseFixture(t, "alpha", "1")
	path := filepath.Join(t.TempDir(), "new.tar")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := packCaseFile(ctx, source, path); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cancelled pack created output")
	}
	if _, err := verifyCaseFile(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := verifyCaseFile(context.Background(), source); err == nil {
		t.Fatal("directory input accepted")
	}
	link := filepath.Join(t.TempDir(), "package-link")
	if err := os.Symlink(filepath.Join(source, "manifest.json"), link); err == nil {
		if _, err := verifyCaseFile(context.Background(), link); err == nil {
			t.Fatal("symlink input accepted")
		}
	}
	for _, args := range [][]string{nil, {source}, {source, "extra", "--output", path}, {source, "--output", ""}} {
		cmd := newCasePackCommand()
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("invalid pack args accepted: %v", args)
		}
	}
	verify := newCaseVerifyCommand()
	verify.SetOut(io.Discard)
	verify.SetErr(io.Discard)
	verify.SetArgs(nil)
	if err := verify.Execute(); err == nil {
		t.Fatal("verify without package accepted")
	}
}

type packageReceiptFailureWriter struct{}

func (packageReceiptFailureWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCasePackReportingFailureKeepsCompletedPackage(t *testing.T) {
	source := writeCentralCaseFixture(t, "alpha", "1")
	path := filepath.Join(t.TempDir(), "completed.tar")
	cmd := newCasePackCommand()
	cmd.SetOut(packageReceiptFailureWriter{})
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{source, "--output", path})
	if err := cmd.Execute(); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("receipt failure: %v", err)
	}
	if _, err := verifyCaseFile(context.Background(), path); err != nil {
		t.Fatalf("completed package lost on reporting failure: %v", err)
	}
}

func TestPackageCleanupDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new.tar")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	owned, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Skip("filesystem cannot remove an open file")
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeOwnedPackage(path, owned); err == nil {
		t.Fatal("cleanup accepted replaced file")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("cleanup deleted unrelated replacement")
	}
}
