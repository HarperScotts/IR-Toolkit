package linux

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"ir-toolkit/internal/model"
)

const maxNetworkTableBytes = 16 << 20
const maxNetworkRows = 65536
const maxNetworkFDs = 1 << 20
const maxNetworkProcesses = 65536

type NetworkCollector struct{}

func (*NetworkCollector) Name() string { return "linux_network" }
func (*NetworkCollector) Collect(ctx context.Context) (any, error) {
	return collectNetwork(ctx, "/proc")
}

type socketRow struct {
	Connection model.NetworkConnection
	Inode      uint64
	UID        uint32
}

var networkTables = [...]struct{ name, protocol, family string }{
	{"tcp", "TCP", "IPv4"}, {"tcp6", "TCP", "IPv6"}, {"udp", "UDP", "IPv4"}, {"udp6", "UDP", "IPv6"},
}

func readProcBounded(root *os.Root, path string, maximum int64) ([]byte, error) {
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("proc read limit: %s", path)
	}
	return data, nil
}

func collectNetwork(ctx context.Context, path string) (model.NetworkSnapshot, error) {
	result := model.NetworkSnapshot{Connections: []model.NetworkConnection{}, Warnings: []string{"Scope: collector network namespace only; live proc observations are not an atomic snapshot."}}
	if ctx == nil {
		return result, fmt.Errorf("network collection context required")
	}
	if err := ctx.Err(); err != nil {
		result.Warnings = append(result.Warnings, "Network collection cancelled; result is incomplete.")
		return result, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		result.Warnings = append(result.Warnings, "Cannot open procfs: "+err.Error())
		return result, err
	}
	defer root.Close()
	namespace, err := root.Readlink("self/ns/net")
	if err != nil {
		result.Warnings = append(result.Warnings, "Cannot determine network namespace: "+err.Error())
		return result, fmt.Errorf("read collector network namespace: %w", err)
	}
	result.NetworkNamespace = namespace
	var failures []error
	var rows []socketRow
	byTable := make([][]socketRow, len(networkTables))
	for index, table := range networkTables {
		data, err := readProcBounded(root, "self/net/"+table.name, maxNetworkTableBytes)
		if err == nil {
			byTable[index], err = parseNetworkTable(ctx, data, table.protocol, table.family, binary.NativeEndian)
		}
		if err == nil && len(byTable[index]) > maxNetworkRows-len(rows) {
			err = fmt.Errorf("network row limit")
			byTable[index] = nil
		}
		if err != nil {
			message := fmt.Sprintf("%s table unavailable/incomplete: %v", table.name, err)
			result.Warnings = append(result.Warnings, message)
			failures = append(failures, fmt.Errorf("%s: %w", table.name, err))
			continue
		}
		rows = append(rows, byTable[index]...)
	}
	if err := ctx.Err(); err != nil {
		result.Warnings = append(result.Warnings, "Network collection cancelled; result is incomplete.")
		return result, err
	}
	wanted := map[uint64]bool{}
	for _, row := range rows {
		if row.Inode != 0 {
			wanted[row.Inode] = true
		}
	}
	owners, ownerErr := socketOwners(ctx, root, namespace, wanted)
	if ownerErr != nil {
		result.Warnings = append(result.Warnings, "Socket owner enumeration incomplete: "+ownerErr.Error())
		failures = append(failures, ownerErr)
	}
	// Recheck table identity/tuple/state/UID after fd enumeration. A changed row
	// remains raw evidence but is not attributed to a process.
	unassigned := 0
	for index, table := range networkTables {
		if len(byTable[index]) == 0 {
			continue
		}
		current := map[socketRow]bool{}
		data, err := readProcBounded(root, "self/net/"+table.name, maxNetworkTableBytes)
		if err == nil {
			var observed []socketRow
			observed, err = parseNetworkTable(ctx, data, table.protocol, table.family, binary.NativeEndian)
			for _, row := range observed {
				current[row] = true
			}
		}
		if err != nil {
			result.Warnings = append(result.Warnings, "Cannot recheck "+table.name+" ownership: "+err.Error())
			failures = append(failures, err)
		}
		for _, row := range byTable[index] {
			connection := row.Connection
			if current[row] {
				connection.PID = owners[row.Inode].PID
				connection.ProcessInstanceID = owners[row.Inode].InstanceID
			}
			if connection.PID == 0 {
				unassigned++
			}
			result.Connections = append(result.Connections, connection)
		}
	}
	endNamespace, err := root.Readlink("self/ns/net")
	if err != nil || namespace != endNamespace {
		result.NetworkNamespace = ""
		for i := range result.Connections {
			result.Connections[i].PID = 0
			result.Connections[i].ProcessInstanceID = ""
		}
		result.Warnings = append(result.Warnings, "Network namespace could not be confirmed unchanged; all PID attribution removed.")
		failures = append(failures, errors.Join(fmt.Errorf("network namespace changed/unavailable"), err))
	}
	if unassigned > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("%d socket rows have no unique observed PID (shared sockets, exit/race or access restrictions may apply).", unassigned))
	}
	if err := ctx.Err(); err != nil {
		failures = append(failures, err)
		result.Warnings = append(result.Warnings, "Network collection cancelled; result is incomplete.")
	}
	return result, errors.Join(failures...)
}

func parseNetworkTable(ctx context.Context, data []byte, protocol, family string, order binary.ByteOrder) ([]socketRow, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > maxNetworkTableBytes {
		return nil, fmt.Errorf("network table byte limit")
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	if !scanner.Scan() {
		return nil, errors.Join(fmt.Errorf("missing network table header"), scanner.Err())
	}
	header := strings.Fields(scanner.Text())
	if len(header) < 4 || header[0] != "sl" || header[1] != "local_address" || (header[2] != "rem_address" && header[2] != "remote_address") || header[3] != "st" || !strings.Contains(scanner.Text(), "inode") {
		return nil, fmt.Errorf("unrecognized network table header")
	}
	rows := []socketRow{}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(rows) >= maxNetworkRows {
			return nil, fmt.Errorf("network row limit")
		}
		if len(fields) < 10 || !strings.HasSuffix(fields[0], ":") {
			return nil, fmt.Errorf("malformed network row")
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 32); err != nil {
			return nil, err
		}
		local, localPort, err := procEndpoint(fields[1], family, order)
		if err != nil {
			return nil, err
		}
		remote, remotePort, err := procEndpoint(fields[2], family, order)
		if err != nil {
			return nil, err
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil || len(fields[3]) != 2 {
			return nil, fmt.Errorf("invalid socket state %q", fields[3])
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			return nil, err
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, err
		}
		rows = append(rows, socketRow{model.NetworkConnection{Protocol: protocol, Family: family, LocalAddress: local, LocalPort: localPort, RemoteAddress: remote, RemotePort: remotePort, State: linuxSocketState(protocol, uint8(state)), SocketInode: strconv.FormatUint(inode, 10), SocketUID: strconv.FormatUint(uid, 10)}, inode, uint32(uid)})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func procEndpoint(value, family string, order binary.ByteOrder) (string, uint32, error) {
	parts := strings.Split(value, ":")
	width := 8
	if family == "IPv6" {
		width = 32
	} else if family != "IPv4" {
		return "", 0, fmt.Errorf("invalid socket family")
	}
	if len(parts) != 2 || len(parts[0]) != width || len(parts[1]) != 4 {
		return "", 0, fmt.Errorf("invalid proc endpoint %q", value)
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}
	var address [16]byte
	for i := 0; i < width/8; i++ {
		word, err := strconv.ParseUint(parts[0][i*8:(i+1)*8], 16, 32)
		if err != nil {
			return "", 0, err
		}
		order.PutUint32(address[i*4:i*4+4], uint32(word))
	}
	if family == "IPv4" {
		return netip.AddrFrom4([4]byte(address[:4])).String(), uint32(port), nil
	}
	return netip.AddrFrom16(address).String(), uint32(port), nil
}

func linuxSocketState(protocol string, state uint8) string {
	if protocol == "UDP" && state == 7 {
		return "UNCONN"
	}
	states := map[uint8]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECEIVED", 4: "FIN_WAIT_1", 5: "FIN_WAIT_2", 6: "TIME_WAIT", 7: "CLOSED", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}
	if name, ok := states[state]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%02X", state)
}
