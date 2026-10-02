package local

import (
	"fmt"
	"ir-toolkit/internal/store"
)

func networkConnectionKey(
	pid uint32,
	connection store.NetworkConnectionRecord,
) string {

	return fmt.Sprintf(
		"%d|%s|%s|%d|%s|%d|%s",
		pid,
		connection.Protocol,
		connection.LocalAddress,
		connection.LocalPort,
		connection.RemoteAddress,
		connection.RemotePort,
		connection.State,
	)
}

func localNetworkItemFromConnection(
	process store.ProcessNetworkRecord,
	connection store.NetworkConnectionRecord,
	kind string,
	external bool,
) NetworkItem {

	id :=
		fmt.Sprintf(
			"network:%d:%s:%s:%d:%s:%d:%s",
			process.PID,
			connection.Protocol,
			connection.LocalAddress,
			connection.LocalPort,
			connection.RemoteAddress,
			connection.RemotePort,
			kind,
		)

	return NetworkItem{
		ID: id,

		PID: process.PID,

		ProcessName: process.ProcessName,

		ProcessPath: process.ProcessPath,

		User: process.User,

		AuthenticationID: process.AuthenticationID,

		Protocol: connection.Protocol,

		Family: connection.Family,

		LocalAddress: connection.LocalAddress,

		LocalPort: connection.LocalPort,

		RemoteAddress: connection.RemoteAddress,

		RemotePort: connection.RemotePort,

		State: connection.State,

		Kind: kind,

		External: external,
	}
}
