package analyzer

import (
	"context"
	"strings"

	"ir-toolkit/internal/model"
)

type ProcessNetworkAnalyzer struct{}

func NewProcessNetworkAnalyzer() *ProcessNetworkAnalyzer {
	return &ProcessNetworkAnalyzer{}
}

func (a *ProcessNetworkAnalyzer) Analyze(
	ctx context.Context,
	processes []model.Process,
	connections []model.NetworkConnection,
) model.NetworkAnalysis {

	result := model.NetworkAnalysis{
		Processes: make(
			[]model.ProcessNetworkAnalysis,
			0,
			len(processes),
		),

		OrphanConnections: make(
			[]model.NetworkConnection,
			0,
		),
	}

	// PID -> result.Processes index
	processMap := make(
		map[uint32]int,
		len(processes),
	)

	// --------------------------------------------------
	// Build process index
	// --------------------------------------------------

	for _, process := range processes {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		startTime := ""

		if !process.StartTime.IsZero() {
			startTime =
				process.StartTime.UTC().Format(
					"2006-01-02T15:04:05.999999999Z07:00",
				)
		}

		item := model.ProcessNetworkAnalysis{
			PID: process.PID,

			ProcessName: process.Name,
			ProcessPath: process.Path,

			CommandLine: process.CommandLine,

			User: process.User,

			SessionID: process.SessionID,

			AuthenticationID: process.AuthenticationID,

			IntegrityLevel: process.IntegrityLevel,

			StartTime: startTime,

			Connections: make(
				[]model.NetworkConnection,
				0,
			),

			Listeners: make(
				[]model.NetworkConnection,
				0,
			),

			ExternalConnections: make(
				[]model.NetworkConnection,
				0,
			),
		}

		index := len(
			result.Processes,
		)

		result.Processes = append(
			result.Processes,
			item,
		)

		processMap[process.PID] =
			index
	}

	// --------------------------------------------------
	// PID -> Network
	// --------------------------------------------------

	for _, connection := range connections {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		index, exists :=
			processMap[connection.PID]

		if !exists {

			result.OrphanConnections =
				append(
					result.OrphanConnections,
					connection,
				)

			continue
		}

		item :=
			&result.Processes[index]

		// 补全网络记录中的进程信息。
		connection.ProcessName =
			item.ProcessName

		connection.ProcessPath =
			item.ProcessPath

		item.Connections =
			append(
				item.Connections,
				connection,
			)

		if isListener(
			connection,
		) {

			item.Listeners =
				append(
					item.Listeners,
					connection,
				)
		}

		if isExternalConnection(
			connection,
		) {

			item.ExternalConnections =
				append(
					item.ExternalConnections,
					connection,
				)
		}
	}

	// --------------------------------------------------
	// Statistics + Indicators
	// --------------------------------------------------

	for i := range result.Processes {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		item :=
			&result.Processes[i]

		item.Indicators =
			generateIndicators(
				item,
			)

		result.Statistics.ProcessCount++

		if len(item.Connections) > 0 {

			result.Statistics.
				ProcessWithNetwork++
		}

		result.Statistics.
			ConnectionCount +=
			uint32(
				len(item.Connections),
			)

		result.Statistics.
			ListenerCount +=
			uint32(
				len(item.Listeners),
			)

		result.Statistics.
			ExternalConnectionCount +=
			uint32(
				len(
					item.ExternalConnections,
				),
			)

		for _, connection := range item.Connections {

			switch strings.ToUpper(
				connection.Protocol,
			) {

			case "TCP":

				result.Statistics.
					TCPCount++

			case "UDP":

				result.Statistics.
					UDPCount++
			}
		}
	}

	return result
}
