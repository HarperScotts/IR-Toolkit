//go:build windows

package windows

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func getProcessCommandLine(
	process windows.Handle,
) string {

	var basicInfo windows.PROCESS_BASIC_INFORMATION

	status := windows.NtQueryInformationProcess(
		process,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&basicInfo),
		uint32(unsafe.Sizeof(basicInfo)),
		nil,
	)

	if status != nil {
		return ""
	}

	if basicInfo.PebBaseAddress == nil {
		return ""
	}

	// Read remote PEB.
	var peb windows.PEB

	if err := windows.ReadProcessMemory(
		process,
		uintptr(unsafe.Pointer(basicInfo.PebBaseAddress)),
		(*byte)(unsafe.Pointer(&peb)),
		unsafe.Sizeof(peb),
		nil,
	); err != nil {
		return ""
	}

	if peb.ProcessParameters == nil {
		return ""
	}

	// Read remote RTL_USER_PROCESS_PARAMETERS.
	var params windows.RTL_USER_PROCESS_PARAMETERS

	if err := windows.ReadProcessMemory(
		process,
		uintptr(unsafe.Pointer(peb.ProcessParameters)),
		(*byte)(unsafe.Pointer(&params)),
		unsafe.Sizeof(params),
		nil,
	); err != nil {
		return ""
	}

	commandLine := params.CommandLine

	if commandLine.Length == 0 ||
		commandLine.Buffer == nil {
		return ""
	}

	// UNICODE_STRING.Length is measured in bytes.
	if commandLine.Length%2 != 0 {
		return ""
	}

	length := int(commandLine.Length / 2)

	// Defensive limit.
	if length <= 0 || length > 32768 {
		return ""
	}

	buffer := make(
		[]uint16,
		length,
	)

	if err := windows.ReadProcessMemory(
		process,
		uintptr(unsafe.Pointer(commandLine.Buffer)),
		(*byte)(unsafe.Pointer(&buffer[0])),
		uintptr(commandLine.Length),
		nil,
	); err != nil {
		return ""
	}

	return windows.UTF16ToString(buffer)
}
