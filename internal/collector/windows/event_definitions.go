//go:build windows

package windows

type WindowsEventDefinition struct {
	ID string

	Channel string

	EventIDs []uint32

	MaxEvents int

	Enabled bool
}
