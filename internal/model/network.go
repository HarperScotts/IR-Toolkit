package model

type NetworkConnection struct {
	PID               uint32 `json:"pid"`
	ProcessInstanceID string `json:"process_instance_id,omitempty"`
	SocketInode       string `json:"socket_inode,omitempty"`
	SocketUID         string `json:"socket_uid,omitempty"`

	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`

	Protocol string `json:"protocol"`
	Family   string `json:"family"`

	LocalAddress  string `json:"local_address"`
	LocalPort     uint32 `json:"local_port"`
	RemoteAddress string `json:"remote_address,omitempty"`
	RemotePort    uint32 `json:"remote_port,omitempty"`

	State string `json:"state,omitempty"`
}

type NetworkSnapshot struct {
	Connections      []NetworkConnection `json:"connections"`
	Warnings         []string            `json:"warnings,omitempty"`
	NetworkNamespace string              `json:"network_namespace,omitempty"`
}
