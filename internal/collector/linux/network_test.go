package linux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const tableHeader = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func tableRow(local, remote, state string, inode uint64) string {
	return fmt.Sprintf("0: %s %s %s 00000000:00000000 00:00000000 00000000 1000 0 %d\n", local, remote, state, inode)
}

func TestProcNetworkEndpoints(t *testing.T) {
	for _, test := range []struct {
		raw, family, want string
		order             binary.ByteOrder
		port              uint32
	}{
		{"0100007F:1F90", "IPv4", "127.0.0.1", binary.LittleEndian, 8080},
		{"7F000001:FFFF", "IPv4", "127.0.0.1", binary.BigEndian, 65535},
		{"00000000000000000000000001000000:01BB", "IPv6", "::1", binary.LittleEndian, 443},
		{"00000000000000000000000000000001:0000", "IPv6", "::1", binary.BigEndian, 0},
	} {
		address, port, err := procEndpoint(test.raw, test.family, test.order)
		if err != nil || address != test.want || port != test.port {
			t.Fatalf("%s: %s:%d %v", test.raw, address, port, err)
		}
	}
	for _, raw := range []string{"0100007F", "0100007G:0001", "0100007F:10000", "127.0.0.1:0001", "0100007F:GGGG"} {
		if _, _, err := procEndpoint(raw, "IPv4", binary.LittleEndian); err == nil {
			t.Fatal("accepted endpoint", raw)
		}
	}
}

func TestProcNetworkTableStrictness(t *testing.T) {
	row := tableRow("0100007F:1F90", "0200000A:01BB", "01", 123)
	rows, err := parseNetworkTable(context.Background(), []byte(tableHeader+row), "TCP", "IPv4", binary.LittleEndian)
	if err != nil || len(rows) != 1 || rows[0].Inode != 123 || rows[0].UID != 1000 || rows[0].Connection.LocalAddress != "127.0.0.1" || rows[0].Connection.RemoteAddress != "10.0.0.2" || rows[0].Connection.State != "ESTABLISHED" {
		t.Fatalf("parse: %+v %v", rows, err)
	}
	for _, bad := range []string{"", row, "bad header\n" + row, tableHeader + "bad row\n", tableHeader + strings.Replace(row, "01 0000", "GG 0000", 1), tableHeader + strings.Replace(row, "1000 0 123", "1000 0 invalid", 1), tableHeader + strings.Repeat("x", 70<<10)} {
		if got, err := parseNetworkTable(context.Background(), []byte(bad), "TCP", "IPv4", binary.LittleEndian); err == nil || got != nil {
			t.Fatal("accepted malformed table", err)
		}
	}
	rows, err = parseNetworkTable(context.Background(), []byte(tableHeader+tableRow("00000000:0035", "00000000:0000", "07", 5)), "UDP", "IPv4", binary.LittleEndian)
	if err != nil || rows[0].Connection.State != "UNCONN" {
		t.Fatal(rows, err)
	}
	if linuxSocketState("TCP", 255) != "UNKNOWN_FF" {
		t.Fatal("unknown kernel state lost")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := parseNetworkTable(ctx, []byte(tableHeader), "TCP", "IPv4", binary.NativeEndian); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}

func writeProcFixture(t *testing.T, root, path, text string) {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func linkProcFixture(t *testing.T, root, path, target string) {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func statFixture(pid uint32, ticks uint64) string {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = "1"
	fields[19] = strconv.FormatUint(ticks, 10)
	return fmt.Sprintf("%d (name (with) parentheses) %s", pid, strings.Join(fields, " "))
}

func networkFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	linkProcFixture(t, root, "self/ns/net", "net:[100]")
	for _, table := range networkTables {
		writeProcFixture(t, root, "self/net/"+table.name, tableHeader)
	}
	for _, pid := range []uint32{42, 43, 44} {
		writeProcFixture(t, root, fmt.Sprintf("%d/stat", pid), statFixture(pid, 100))
		ns := "net:[100]"
		if pid == 44 {
			ns = "net:[200]"
		}
		linkProcFixture(t, root, fmt.Sprintf("%d/ns/net", pid), ns)
		if err := os.MkdirAll(filepath.Join(root, fmt.Sprintf("%d/fd", pid)), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeProcFixture(t, root, "self/net/tcp", tableHeader+tableRow("0100007F:1F90", "0200000A:01BB", "01", 123)+tableRow("00000000:0050", "00000000:0000", "0A", 124)+tableRow("0100007F:0001", "0200000A:0002", "06", 0))
	writeProcFixture(t, root, "self/net/tcp6", tableHeader+tableRow("00000000000000000000000001000000:1F90", "00000000000000000000000000000000:0000", "0A", 125))
	writeProcFixture(t, root, "self/net/udp", tableHeader+tableRow("00000000:0035", "00000000:0000", "07", 126))
	for _, item := range []struct {
		pid, fd int
		inode   uint64
	}{{42, 3, 123}, {42, 4, 124}, {42, 5, 126}, {43, 3, 124}, {44, 3, 125}} {
		linkProcFixture(t, root, fmt.Sprintf("%d/fd/%d", item.pid, item.fd), fmt.Sprintf("socket:[%d]", item.inode))
	}
	return root
}

func TestNetworkCollectionObservedOwnersAndScope(t *testing.T) {
	if binary.NativeEndian.Uint32([]byte{1, 0, 0, 0}) != 1 {
		t.Skip("fixture is little endian; endpoint parser tests both endian orders")
	}
	snapshot, err := collectNetwork(context.Background(), networkFixture(t))
	if err != nil || len(snapshot.Connections) != 5 {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	for index, connection := range snapshot.Connections {
		wantPID := uint32(0)
		if index == 0 || index == 4 {
			wantPID = 42
		}
		if connection.PID != wantPID {
			t.Fatalf("row %d PID=%d want %d", index, connection.PID, wantPID)
		}
		if wantPID != 0 && connection.ProcessInstanceID != "linux-proc:42:100" {
			t.Fatalf("instance lost: %+v", connection)
		}
		if wantPID == 0 && connection.ProcessInstanceID != "" {
			t.Fatal("ambiguous owner has instance key")
		}
	}
	if len(snapshot.Warnings) < 2 {
		t.Fatal("scope and unattributed rows not disclosed")
	}
	if snapshot.NetworkNamespace != "net:[100]" || snapshot.Connections[0].SocketInode != "123" || snapshot.Connections[0].SocketUID != "1000" {
		t.Fatal("socket ownership source evidence lost")
	}
}

func TestNetworkCollectionPartialFailuresAreRecorded(t *testing.T) {
	root := networkFixture(t)
	if err := os.Remove(filepath.Join(root, "self/net/tcp6")); err != nil {
		t.Fatal(err)
	}
	writeProcFixture(t, root, "43/stat", "invalid stat")
	snapshot, err := collectNetwork(context.Background(), root)
	if err == nil || len(snapshot.Connections) != 4 || !strings.Contains(strings.Join(snapshot.Warnings, " "), "tcp6") {
		t.Fatalf("partial loss hidden: %+v %v", snapshot, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := collectNetwork(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestProcInstanceIdentity(t *testing.T) {
	got, err := procInstance([]byte(statFixture(42, 12345)), 42)
	if err != nil || got != "linux-proc:42:12345" {
		t.Fatal(got, err)
	}
	for _, text := range []string{statFixture(43, 12345), "42 (short) S 1", strings.Replace(statFixture(42, 12345), "12345", "-1", 1)} {
		if _, err := procInstance([]byte(text), 42); err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
}

func FuzzProcNetworkTable(f *testing.F) {
	f.Add([]byte(tableHeader + tableRow("0100007F:0050", "00000000:0000", "0A", 123)))
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := parseNetworkTable(context.Background(), data, "TCP", "IPv4", binary.NativeEndian)
		if err != nil && rows != nil {
			t.Fatal("partial table on parse failure")
		}
		if len(rows) > maxNetworkRows {
			t.Fatal("row limit ignored")
		}
	})
}
