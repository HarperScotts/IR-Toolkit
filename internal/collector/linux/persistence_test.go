package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ir-toolkit/internal/analyzer"
	"ir-toolkit/internal/model"
)

func fixturePersistenceLimits() persistenceLimits { return persistenceLimits{100, 1000, 1024, 8192} }

func TestPersistenceRawInventory(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"etc/systemd/system/Alpha.service":                 "[Service]\nExecStart=/bin/true\n",
		"etc/systemd/system/beta.service":                  "[Service]\nExecStart=/bin/false\n",
		"etc/systemd/system/Alpha.service.d/override.conf": "[Service]\nExecStart=\n",
		"etc/systemd/system/service.d/global.conf":         "[Service]\nUser=nobody\n",
		"etc/systemd/system/backup.timer":                  "[Timer]\nOnCalendar=daily\n",
		"etc/crontab":                                      "# cron\n* * * * * root /bin/true\n",
		"etc/cron.d/binary":                                "# raw\x00\xff\r\n",
		"etc/cron.daily/empty":                             "",
		"var/spool/cron/crontabs/alice":                    "@reboot /bin/true\n",
	}
	for name, data := range files {
		writeProcFixture(t, root, name, data)
	}
	writeProcFixture(t, root, "etc/systemd/system/ignored.txt", "not a unit")
	writeProcFixture(t, root, "etc/systemd/system/unrelated/nested.service", "outside traversal")
	linkProcFixture(t, root, "etc/systemd/system/masked.service", "/dev/null")
	linkProcFixture(t, root, "etc/systemd/system/multi-user.target.wants/Alpha.service", "../Alpha.service")
	linkProcFixture(t, root, "etc/cron.d/outside", "/never-read-this")
	// Never follow a descendant symlink directory or its contents.
	linkProcFixture(t, root, "etc/systemd/system/linked.service.d", "unrelated")
	snapshot, err := collectPersistence(context.Background(), root, fixturePersistenceLimits())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.LinuxArtifacts) != len(files)+4 {
		t.Fatalf("unexpected inventory: %+v", snapshot.LinuxArtifacts)
	}
	for _, item := range snapshot.LinuxArtifacts {
		if item.LinkTarget != "" {
			if item.SHA256 != "" || item.Content != nil || item.ReadError != "" {
				t.Fatalf("followed link: %+v", item)
			}
			continue
		}
		data, ok := files[strings.TrimPrefix(item.Path, "/")]
		sum := sha256.Sum256([]byte(data))
		if !ok || !bytes.Equal(item.Content, []byte(data)) || item.SHA256 != fmt.Sprintf("%x", sum) || item.ReadError != "" || item.Mode == "" || item.ModifiedAt.IsZero() {
			t.Fatalf("lost source bytes/metadata: %+v", item)
		}
	}
	missing, observed := 0, 0
	for _, source := range snapshot.LinuxSources {
		switch source.Status {
		case "missing":
			missing++
		case "observed":
			observed++
		default:
			t.Fatalf("source: %+v", source)
		}
	}
	if missing == 0 || observed == 0 {
		t.Fatal("missing and observed sources conflated")
	}
	analysis := analyzer.AnalyzePersistence(context.Background(), snapshot, model.NetworkAnalysis{})
	if analysis.Statistics.LinuxArtifactCount != uint32(len(snapshot.LinuxArtifacts)) || len(analysis.Findings) != 0 || analysis.Statistics.ServiceCount != 0 || analysis.Statistics.ScheduledTaskCount != 0 {
		t.Fatalf("Linux raw candidates treated as Windows persistence: %+v", analysis)
	}
}

func TestPersistenceLimitsAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name   string
		limits persistenceLimits
	}{
		{"file", persistenceLimits{100, 1000, 1, 8192}},
		{"total", persistenceLimits{100, 1000, 1024, 1}},
		{"artifacts", persistenceLimits{1, 1000, 1024, 8192}},
		{"entries", persistenceLimits{100, 1, 1024, 8192}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeProcFixture(t, root, "etc/systemd/system/a.service", "data")
			writeProcFixture(t, root, "etc/systemd/system/b.service", "other")
			snapshot, err := collectPersistence(context.Background(), root, test.limits)
			if err == nil || len(snapshot.Warnings) <= 3 {
				t.Fatal("limit silently truncated", err)
			}
			for _, item := range snapshot.LinuxArtifacts {
				if item.ReadError != "" && (item.Content != nil || item.SHA256 != "") {
					t.Fatal("failed evidence has successful content/hash")
				}
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if snapshot, err := collectPersistence(ctx, t.TempDir(), fixturePersistenceLimits()); !errors.Is(err, context.Canceled) || len(snapshot.Warnings) <= 3 {
		t.Fatal("cancel lost", err)
	}
}

func TestPersistenceRejectsReplacedFile(t *testing.T) {
	rootPath := t.TempDir()
	writeProcFixture(t, rootPath, "unit.service", "old")
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	before, err := root.Stat("unit.service")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rootPath, "unit.service"), filepath.Join(rootPath, "old.service")); err != nil {
		t.Fatal(err)
	}
	writeProcFixture(t, rootPath, "unit.service", "new")
	s := persistenceScan{ctx: context.Background(), limits: fixturePersistenceLimits()}
	var artifact model.LinuxPersistenceArtifact
	if err := s.readContent(root, "unit.service", before, &artifact); err == nil || artifact.Content != nil || artifact.SHA256 != "" {
		t.Fatal("replaced evidence accepted", err)
	}
}

func TestPersistenceUnitFilenameOccupiedByDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/systemd/system/demo.service"), 0700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := collectPersistence(context.Background(), root, fixturePersistenceLimits())
	if err == nil || len(snapshot.LinuxArtifacts) != 1 || snapshot.LinuxArtifacts[0].ReadError == "" || snapshot.LinuxArtifacts[0].Content != nil {
		t.Fatal("directory falsely treated as absent filename", snapshot, err)
	}
	for _, source := range snapshot.LinuxSources {
		if source.Path == "/etc/systemd/system" && source.Status != "partial" {
			t.Fatal("directory source completeness lost", source)
		}
	}
}
