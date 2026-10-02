//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"ir-toolkit/internal/model"
)

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPIDAll = 5
	udpTableOwnerPID    = 1
)

var (
	iphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")

	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

type NetworkCollector struct{}

func (c *NetworkCollector) Name() string {
	return "windows_network"
}

func (c *NetworkCollector) Collect(
	ctx context.Context,
) (any, error) {

	connections := make(
		[]model.NetworkConnection,
		0,
		256,
	)

	tcp4, err := collectTCPTable(
		afInet,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"collect tcp4: %w",
			err,
		)
	}

	connections = append(
		connections,
		tcp4...,
	)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	tcp6, err := collectTCPTable(
		afInet6,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"collect tcp6: %w",
			err,
		)
	}

	connections = append(
		connections,
		tcp6...,
	)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	udp4, err := collectUDPTable(
		afInet,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"collect udp4: %w",
			err,
		)
	}

	connections = append(
		connections,
		udp4...,
	)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	udp6, err := collectUDPTable(
		afInet6,
	)

	if err != nil {
		return nil, fmt.Errorf(
			"collect udp6: %w",
			err,
		)
	}

	connections = append(
		connections,
		udp6...,
	)

	return model.NetworkSnapshot{
		Connections: connections,
	}, nil
}

func collectTCPTable(
	family uint32,
) ([]model.NetworkConnection, error) {

	data, err := getExtendedTable(
		procGetExtendedTcpTable,
		family,
		tcpTableOwnerPIDAll,
	)

	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf(
			"invalid tcp table",
		)
	}

	count := binary.LittleEndian.Uint32(
		data[:4],
	)

	offset := 4

	var rowSize int

	switch family {

	case afInet:
		rowSize = 24

	case afInet6:
		rowSize = 56

	default:
		return nil, fmt.Errorf(
			"unsupported tcp address family: %d",
			family,
		)
	}

	expected := offset + int(count)*rowSize

	if expected > len(data) {
		return nil, fmt.Errorf(
			"invalid tcp table size: count=%d size=%d",
			count,
			len(data),
		)
	}

	result := make(
		[]model.NetworkConnection,
		0,
		count,
	)

	for i := uint32(0); i < count; i++ {

		row := data[offset+int(i)*rowSize : offset+int(i+1)*rowSize]

		var conn model.NetworkConnection

		if family == afInet {
			conn = parseTCP4(row)
		} else {
			conn = parseTCP6(row)
		}

		result = append(
			result,
			conn,
		)
	}

	return result, nil
}

func parseTCP4(
	row []byte,
) model.NetworkConnection {

	/*
		MIB_TCPROW_OWNER_PID:

		DWORD dwState;       // 0
		DWORD dwLocalAddr;   // 4
		DWORD dwLocalPort;   // 8
		DWORD dwRemoteAddr;  // 12
		DWORD dwRemotePort;  // 16
		DWORD dwOwningPid;   // 20
	*/

	state := binary.LittleEndian.Uint32(
		row[0:4],
	)

	localAddr := binary.LittleEndian.Uint32(
		row[4:8],
	)

	localPortRaw := binary.LittleEndian.Uint32(
		row[8:12],
	)

	remoteAddr := binary.LittleEndian.Uint32(
		row[12:16],
	)

	remotePortRaw := binary.LittleEndian.Uint32(
		row[16:20],
	)

	pid := binary.LittleEndian.Uint32(
		row[20:24],
	)

	return model.NetworkConnection{
		PID:      pid,
		Protocol: "TCP",
		Family:   "IPv4",

		LocalAddress: ipv4FromDWORD(
			localAddr,
		),

		LocalPort: networkPort(
			localPortRaw,
		),

		RemoteAddress: ipv4FromDWORD(
			remoteAddr,
		),

		RemotePort: networkPort(
			remotePortRaw,
		),

		State: tcpStateName(state),
	}
}

func parseTCP6(
	row []byte,
) model.NetworkConnection {

	/*
		MIB_TCP6ROW_OWNER_PID:

		UCHAR  ucLocalAddr[16];      // 0
		DWORD  dwLocalScopeId;      // 16
		DWORD  dwLocalPort;         // 20
		UCHAR  ucRemoteAddr[16];    // 24
		DWORD  dwRemoteScopeId;     // 40
		DWORD  dwRemotePort;        // 44
		DWORD  dwState;             // 48
		DWORD  dwOwningPid;         // 52
	*/

	localAddr := net.IP(
		append(
			[]byte(nil),
			row[0:16]...,
		),
	)

	localPortRaw := binary.LittleEndian.Uint32(
		row[20:24],
	)

	remoteAddr := net.IP(
		append(
			[]byte(nil),
			row[24:40]...,
		),
	)

	remotePortRaw := binary.LittleEndian.Uint32(
		row[44:48],
	)

	state := binary.LittleEndian.Uint32(
		row[48:52],
	)

	pid := binary.LittleEndian.Uint32(
		row[52:56],
	)

	return model.NetworkConnection{
		PID:      pid,
		Protocol: "TCP",
		Family:   "IPv6",

		LocalAddress: localAddr.String(),

		LocalPort: networkPort(
			localPortRaw,
		),

		RemoteAddress: remoteAddr.String(),

		RemotePort: networkPort(
			remotePortRaw,
		),

		State: tcpStateName(state),
	}
}

func collectUDPTable(
	family uint32,
) ([]model.NetworkConnection, error) {

	data, err := getExtendedTable(
		procGetExtendedUdpTable,
		family,
		udpTableOwnerPID,
	)

	if err != nil {
		return nil, err
	}

	if len(data) < 4 {
		return nil, fmt.Errorf(
			"invalid udp table",
		)
	}

	count := binary.LittleEndian.Uint32(
		data[:4],
	)

	offset := 4

	var rowSize int

	switch family {

	case afInet:
		rowSize = 12

	case afInet6:
		rowSize = 28

	default:
		return nil, fmt.Errorf(
			"unsupported udp address family: %d",
			family,
		)
	}

	expected := offset + int(count)*rowSize

	if expected > len(data) {
		return nil, fmt.Errorf(
			"invalid udp table size",
		)
	}

	result := make(
		[]model.NetworkConnection,
		0,
		count,
	)

	for i := uint32(0); i < count; i++ {

		row := data[offset+int(i)*rowSize : offset+int(i+1)*rowSize]

		var conn model.NetworkConnection

		if family == afInet {
			conn = parseUDP4(row)
		} else {
			conn = parseUDP6(row)
		}

		result = append(
			result,
			conn,
		)
	}

	return result, nil
}

func parseUDP4(
	row []byte,
) model.NetworkConnection {

	/*
		MIB_UDPROW_OWNER_PID:

		DWORD dwLocalAddr;   // 0
		DWORD dwLocalPort;   // 4
		DWORD dwOwningPid;   // 8
	*/

	localAddr := binary.LittleEndian.Uint32(
		row[0:4],
	)

	localPortRaw := binary.LittleEndian.Uint32(
		row[4:8],
	)

	pid := binary.LittleEndian.Uint32(
		row[8:12],
	)

	return model.NetworkConnection{
		PID:      pid,
		Protocol: "UDP",
		Family:   "IPv4",

		LocalAddress: ipv4FromDWORD(
			localAddr,
		),

		LocalPort: networkPort(
			localPortRaw,
		),
	}
}

func parseUDP6(
	row []byte,
) model.NetworkConnection {

	/*
		MIB_UDP6ROW_OWNER_PID:

		UCHAR  ucLocalAddr[16]; // 0
		DWORD  dwLocalScopeId; // 16
		DWORD  dwLocalPort;    // 20
		DWORD  dwOwningPid;    // 24
	*/

	localAddr := net.IP(
		append(
			[]byte(nil),
			row[0:16]...,
		),
	)

	localPortRaw := binary.LittleEndian.Uint32(
		row[20:24],
	)

	pid := binary.LittleEndian.Uint32(
		row[24:28],
	)

	return model.NetworkConnection{
		PID:      pid,
		Protocol: "UDP",
		Family:   "IPv6",

		LocalAddress: localAddr.String(),

		LocalPort: networkPort(
			localPortRaw,
		),
	}
}

func getExtendedTable(
	proc *windows.LazyProc,
	family uint32,
	tableClass uint32,
) ([]byte, error) {

	var size uint32

	// First call obtains required buffer size.
	r1, _, _ := proc.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tableClass),
		0,
	)

	errCode := windows.Errno(r1)

	if errCode != windows.ERROR_INSUFFICIENT_BUFFER &&
		errCode != windows.ERROR_SUCCESS {

		return nil, errCode
	}

	if size == 0 {
		return []byte{0, 0, 0, 0}, nil
	}

	buffer := make(
		[]byte,
		size,
	)

	for {

		r1, _, callErr := proc.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&size)),
			1,
			uintptr(family),
			uintptr(tableClass),
			0,
		)

		if r1 == 0 {
			return buffer[:size], nil
		}

		if windows.Errno(r1) != windows.ERROR_INSUFFICIENT_BUFFER {
			if callErr != syscall.Errno(0) {
				return nil, callErr
			}

			return nil, windows.Errno(r1)
		}

		buffer = make(
			[]byte,
			size,
		)
	}
}

func ipv4FromDWORD(
	value uint32,
) string {

	return net.IPv4(
		byte(value),
		byte(value>>8),
		byte(value>>16),
		byte(value>>24),
	).String()
}

func networkPort(
	value uint32,
) uint32 {

	// Windows stores ports in network byte order.
	return uint32(
		(value>>8)&0xff |
			(value&0xff)<<8,
	)
}

func tcpStateName(
	state uint32,
) string {

	switch state {

	case 1:
		return "CLOSED"

	case 2:
		return "LISTEN"

	case 3:
		return "SYN_SENT"

	case 4:
		return "SYN_RECEIVED"

	case 5:
		return "ESTABLISHED"

	case 6:
		return "FIN_WAIT_1"

	case 7:
		return "FIN_WAIT_2"

	case 8:
		return "CLOSE_WAIT"

	case 9:
		return "CLOSING"

	case 10:
		return "LAST_ACK"

	case 11:
		return "TIME_WAIT"

	case 12:
		return "DELETE_TCB"

	default:
		return "UNKNOWN"
	}
}
