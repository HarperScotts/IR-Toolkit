package model

// Developer/acceptance metadata, separate from the case evidence schema.
type LinuxLogin1Inspection struct {
	OS           string               `json:"os"`
	Architecture string               `json:"architecture"`
	EffectiveUID int                  `json:"effective_uid"`
	Tool         LinuxLogin1ToolProbe `json:"tool"`
	Snapshot     LinuxLogin1Snapshot  `json:"snapshot"`
}

type LinuxLogin1ToolProbe struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments"`
	Status     string   `json:"status"`
	Content    []byte   `json:"content,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Stderr     []byte   `json:"stderr,omitempty"`
	Error      string   `json:"error,omitempty"`
}
