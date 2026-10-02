package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func isWebServerProcess(
	process model.Process,
) bool {

	name := strings.ToLower(
		process.Name,
	)

	switch name {

	case "w3wp.exe",
		"nginx.exe",
		"nginx",
		"httpd.exe",
		"httpd",
		"apache2",
		"php-cgi.exe",
		"php-fpm.exe",
		"php-fpm":

		return true
	}

	// Java itself太常见，不直接认为是 Web Server。
	// 只有 command line 出现典型 Web 容器特征才判断。
	if name == "java.exe" ||
		name == "java" {

		commandLine :=
			strings.ToLower(
				process.CommandLine,
			)

		if strings.Contains(
			commandLine,
			"tomcat",
		) ||
			strings.Contains(
				commandLine,
				"catalina",
			) ||
			strings.Contains(
				commandLine,
				"jetty",
			) {

			return true
		}
	}

	return false
}

func isShellProcessName(
	name string,
) bool {

	switch strings.ToLower(name) {

	case "cmd.exe",
		"powershell.exe",
		"pwsh.exe",
		"sh",
		"bash",
		"dash",
		"zsh",
		"ksh":

		return true
	}

	return false
}

func isScriptOrTransferProcess(
	name string,
) bool {

	switch strings.ToLower(name) {

	case "powershell.exe",
		"pwsh.exe",

		"curl.exe",
		"curl",

		"wget.exe",
		"wget",

		"certutil.exe",
		"bitsadmin.exe",

		"mshta.exe",
		"wscript.exe",
		"cscript.exe":

		return true
	}

	return false
}

func buildAncestorChain(
	pid uint32,
	processMap map[uint32]model.Process,
) []model.Process {

	chain := make(
		[]model.Process,
		0,
		8,
	)

	visited := make(
		map[uint32]struct{},
	)

	currentPID := pid

	for depth := 0; depth < 16; depth++ {

		process, exists :=
			processMap[currentPID]

		if !exists {
			break
		}

		if _, exists :=
			visited[currentPID]; exists {

			break
		}

		visited[currentPID] =
			struct{}{}

		// prepend，使最终结果：
		//
		// w3wp -> cmd -> powershell
		chain = append(
			[]model.Process{
				process,
			},
			chain...,
		)

		if process.PPID == 0 ||
			process.PPID ==
				process.PID {

			break
		}

		currentPID =
			process.PPID
	}

	return chain
}

func chainHasWebServer(
	chain []model.Process,
) bool {

	for _, process := range chain {

		if isWebServerProcess(
			process,
		) {
			return true
		}
	}

	return false
}

func chainHasShell(
	chain []model.Process,
) bool {

	for _, process := range chain {

		if isShellProcessName(
			process.Name,
		) {
			return true
		}
	}

	return false
}

func processIDs(
	chain []model.Process,
) []uint32 {

	result := make(
		[]uint32,
		0,
		len(chain),
	)

	for _, process := range chain {

		result =
			append(
				result,
				process.PID,
			)
	}

	return result
}

func formatProcessChain(
	chain []model.Process,
) string {

	parts := make(
		[]string,
		0,
		len(chain),
	)

	for _, process := range chain {

		parts =
			append(
				parts,
				fmt.Sprintf(
					"%s(%d)",
					process.Name,
					process.PID,
				),
			)
	}

	return strings.Join(
		parts,
		" -> ",
	)
}
