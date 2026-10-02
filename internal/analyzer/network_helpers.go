package analyzer

import (
	"net"
	"strings"

	"ir-toolkit/internal/model"
)

func isListener(
	connection model.NetworkConnection,
) bool {

	// UDP 没有 TCP LISTEN 状态。
	// 当前阶段把 UDP bound endpoint 统一归入 Listeners。
	if strings.EqualFold(
		connection.Protocol,
		"UDP",
	) {
		return true
	}

	return strings.EqualFold(
		connection.State,
		"LISTEN",
	)
}

func isExternalConnection(
	connection model.NetworkConnection,
) bool {

	if connection.RemoteAddress == "" {
		return false
	}

	if connection.RemotePort == 0 {
		return false
	}

	// Listener 不属于主动外连。
	if isListener(connection) {
		return false
	}

	ip := net.ParseIP(
		connection.RemoteAddress,
	)

	if ip == nil {
		return false
	}

	return isPublicRemoteIP(ip)
}

func isPublicRemoteIP(ip net.IP) bool {

	if ip == nil {
		return false
	}

	// 0.0.0.0 / ::
	if ip.IsUnspecified() {
		return false
	}

	// 127.0.0.0/8 / ::1
	if ip.IsLoopback() {
		return false
	}

	// RFC1918 IPv4 + IPv6 ULA
	if ip.IsPrivate() {
		return false
	}

	// 169.254.0.0/16 / fe80::/10
	if ip.IsLinkLocalUnicast() {
		return false
	}

	if ip.IsLinkLocalMulticast() {
		return false
	}

	if ip.IsMulticast() {
		return false
	}

	// IPv4 limited broadcast
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 255 &&
			ip4[1] == 255 &&
			ip4[2] == 255 &&
			ip4[3] == 255 {

			return false
		}

		// Carrier-grade NAT:
		// 100.64.0.0/10
		//
		// 在企业环境中通常不应直接视为公网 C2。
		if ip4[0] == 100 &&
			ip4[1] >= 64 &&
			ip4[1] <= 127 {

			return false
		}
	}

	return true
}
