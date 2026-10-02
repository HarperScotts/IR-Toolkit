package web

import (
	"fmt"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	maxProcessContextTimelineEvents = 200
)

type ProcessContextResponse struct {
	PID uint32 `json:"pid"`

	AuthenticationID string `json:"authentication_id,omitempty"`

	LoginSession *ProcessLoginContext `json:"login_session,omitempty"`

	Network []ProcessNetworkContext `json:"network"`

	HistoricalProcesses []ProcessHistoricalContext `json:"historical_processes"`

	PowerShell []ProcessPowerShellContext `json:"powershell"`

	Timeline []ProcessTimelineContext `json:"timeline"`

	Statistics ProcessContextStatistics `json:"statistics"`
}

type ProcessContextStatistics struct {
	NetworkCount uint32 `json:"network_count"`

	ListenerCount uint32 `json:"listener_count"`

	ExternalNetworkCount uint32 `json:"external_network_count"`

	HistoricalProcessCount uint32 `json:"historical_process_count"`

	PowerShellCount uint32 `json:"powershell_count"`

	TimelineEventCount uint32 `json:"timeline_event_count"`
}

type ProcessLoginContext struct {
	LogonID string `json:"logon_id,omitempty"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	LogonType uint32 `json:"logon_type,omitempty"`

	LogonTypeName string `json:"logon_type_name,omitempty"`

	SourceIP string `json:"source_ip,omitempty"`

	SourcePort string `json:"source_port,omitempty"`

	Workstation string `json:"workstation,omitempty"`

	AuthenticationPackage string `json:"authentication_package,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	Privileged bool `json:"privileged"`

	Privileges string `json:"privileges,omitempty"`

	MatchType string `json:"match_type"`

	Confidence string `json:"confidence"`
}

type ProcessNetworkContext struct {
	Protocol string `json:"protocol,omitempty"`

	Family string `json:"family,omitempty"`

	LocalAddress string `json:"local_address,omitempty"`

	LocalPort uint32 `json:"local_port,omitempty"`

	RemoteAddress string `json:"remote_address,omitempty"`

	RemotePort uint32 `json:"remote_port,omitempty"`

	State string `json:"state,omitempty"`

	External bool `json:"external"`

	Listener bool `json:"listener"`

	PID uint32 `json:"pid"`

	MatchType string `json:"match_type,omitempty"`
}

type ProcessHistoricalContext struct {
	ID string `json:"id"`

	PID uint32 `json:"pid"`

	PPID uint32 `json:"ppid,omitempty"`

	ProcessName string `json:"process_name,omitempty"`

	ProcessPath string `json:"process_path,omitempty"`

	CommandLine string `json:"command_line,omitempty"`

	ParentProcessName string `json:"parent_process_name,omitempty"`

	CurrentProcessPath string `json:"current_process_path,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	Timestamp time.Time `json:"timestamp"`

	TokenElevationType string `json:"token_elevation_type,omitempty"`

	MandatoryLabel string `json:"mandatory_label,omitempty"`

	MatchedLogin bool `json:"matched_login"`

	MatchType string `json:"match_type"`

	Confidence string `json:"confidence"`
}

type ProcessPowerShellContext struct {
	ScriptBlockID string `json:"script_block_id,omitempty"`

	Timestamp time.Time `json:"timestamp"`

	Path string `json:"path,omitempty"`

	SHA256 string `json:"sha256,omitempty"`

	Complete bool `json:"complete"`

	FragmentCount uint32 `json:"fragment_count,omitempty"`

	ScriptText string `json:"script_text,omitempty"`

	Indicators []string `json:"indicators,omitempty"`

	HistoricalProcessID string `json:"historical_process_id,omitempty"`

	PID uint32 `json:"pid,omitempty"`

	User string `json:"user,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	Confidence string `json:"confidence,omitempty"`

	MatchBasis string `json:"match_basis,omitempty"`

	RelatedProcessName string `json:"related_process_name,omitempty"`

	RelatedCommandLine string `json:"related_command_line,omitempty"`

	LastTimestamp time.Time `json:"last_timestamp,omitempty"`
}

type ProcessTimelineContext struct {
	ID string `json:"id,omitempty"`

	Timestamp time.Time `json:"timestamp,omitempty"`

	Category string `json:"category,omitempty"`

	Type string `json:"type,omitempty"`

	Description string `json:"description,omitempty"`

	Severity string `json:"severity,omitempty"`

	MatchType string `json:"match_type,omitempty"`

	Confidence string `json:"confidence,omitempty"`
}

type webHistoricalProcess struct {
	ID string `json:"id"`

	Timestamp time.Time `json:"timestamp"`

	PID uint32 `json:"pid"`

	ParentPID uint32 `json:"parent_pid"`

	ProcessName string `json:"process_name"`

	ProcessPath string `json:"process_path"`

	CommandLine string `json:"command_line,omitempty"`

	ParentProcessName string `json:"parent_process_name,omitempty"`

	User string `json:"user,omitempty"`

	Domain string `json:"domain,omitempty"`

	LogonID string `json:"logon_id,omitempty"`

	TokenElevationType string `json:"token_elevation_type,omitempty"`

	MandatoryLabel string `json:"mandatory_label,omitempty"`

	MatchedLogin bool `json:"matched_login"`

	CurrentProcess bool `json:"current_process"`

	CurrentProcessPath string `json:"current_process_path,omitempty"`
}

type webProcessHistoryAnalysis struct {
	Processes []webHistoricalProcess `json:"processes"`
}

type webNetworkAnalysis struct {
	Processes []webProcessNetworkAnalysis `json:"processes"`
}

type webProcessNetworkAnalysis struct {
	PID uint32 `json:"pid"`

	ProcessName string `json:"process_name,omitempty"`

	ProcessPath string `json:"process_path,omitempty"`

	User string `json:"user,omitempty"`

	SessionID uint32 `json:"session_id,omitempty"`

	AuthenticationID string `json:"authentication_id,omitempty"`

	IntegrityLevel string `json:"integrity_level,omitempty"`

	StartTime time.Time `json:"start_time,omitempty"`

	Connections []webNetworkConnection `json:"connections,omitempty"`

	Listeners []webNetworkConnection `json:"listeners,omitempty"`

	ExternalConnections []webNetworkConnection `json:"external_connections,omitempty"`
}

type webNetworkConnection struct {
	PID uint32 `json:"pid"`

	ProcessName string `json:"process_name,omitempty"`

	ProcessPath string `json:"process_path,omitempty"`

	Protocol string `json:"protocol,omitempty"`

	Family string `json:"family,omitempty"`

	LocalAddress string `json:"local_address,omitempty"`

	LocalPort uint32 `json:"local_port,omitempty"`

	RemoteAddress string `json:"remote_address,omitempty"`

	RemotePort uint32 `json:"remote_port,omitempty"`

	State string `json:"state,omitempty"`
}

func (s *Server) handleProcessContext(
	writer http.ResponseWriter,
	request *http.Request,
) {

	rawPID :=
		request.PathValue(
			"pid",
		)

	parsed, err :=
		strconv.ParseUint(
			rawPID,
			10,
			32,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusBadRequest,
			"invalid process pid",
		)

		return
	}

	pid :=
		uint32(parsed)

	selected,
		found,
		err :=
		s.store.ProcessByPID(
			pid,
		)

	if err != nil {

		writeAPIError(
			writer,
			http.StatusInternalServerError,
			fmt.Sprintf(
				"load process evidence: %v",
				err,
			),
		)

		return
	}

	if !found {

		writeAPIError(
			writer,
			http.StatusNotFound,
			"process not found",
		)

		return
	}

	response :=
		ProcessContextResponse{
			PID: pid,

			AuthenticationID: selected.AuthenticationID,

			Network: []ProcessNetworkContext{},

			HistoricalProcesses: []ProcessHistoricalContext{},

			PowerShell: []ProcessPowerShellContext{},

			Timeline: []ProcessTimelineContext{},
		}

	/*
		各类关联失败不应该导致整个 context API 失败。

		Case 的某些证据源可能本来就不存在。
	*/

	response.LoginSession =
		s.findProcessLoginContext(
			selected,
		)

	response.Network =
		s.findProcessNetworkContext(
			selected,
		)

	response.HistoricalProcesses =
		s.findProcessHistoricalContext(
			selected,
		)

	response.PowerShell =
		s.findProcessPowerShellContext(
			selected,
			response.HistoricalProcesses,
		)

	response.Timeline =
		s.findProcessTimelineContext(
			selected,
		)

	for _, network := range response.Network {

		if network.External {

			response.Statistics.
				ExternalNetworkCount++
		}

		if network.Listener {

			response.Statistics.
				ListenerCount++
		}
	}

	response.Statistics.NetworkCount =
		uint32(
			len(response.Network),
		)

	response.Statistics.HistoricalProcessCount =
		uint32(
			len(response.HistoricalProcesses),
		)

	response.Statistics.PowerShellCount =
		uint32(
			len(response.PowerShell),
		)

	response.Statistics.TimelineEventCount =
		uint32(
			len(response.Timeline),
		)

	writeJSON(
		writer,
		http.StatusOK,
		response,
	)
}

func normalizeLogonID(
	value string,
) string {

	value =
		strings.TrimSpace(
			strings.ToLower(
				value,
			),
		)

	value =
		strings.TrimPrefix(
			value,
			"0x",
		)

	value =
		strings.TrimLeft(
			value,
			"0",
		)

	if value == "" {
		value = "0"
	}

	return value
}

func sameLogonID(
	left string,
	right string,
) bool {

	if left == "" ||
		right == "" {

		return false
	}

	return normalizeLogonID(left) ==
		normalizeLogonID(right)
}

func (s *Server) findProcessLoginContext(
	process model.Process,
) *ProcessLoginContext {

	if process.AuthenticationID == "" {
		return nil
	}

	session,
		found,
		err :=
		s.store.LoginByLogonID(
			process.AuthenticationID,
		)

	if err != nil ||
		!found {

		return nil
	}

	return &ProcessLoginContext{
		LogonID: session.LogonID,

		User: session.User,

		Domain: session.Domain,

		LogonType: session.LogonType,

		LogonTypeName: session.LogonTypeName,

		SourceIP: session.SourceIP,

		SourcePort: session.SourcePort,

		Workstation: session.Workstation,

		AuthenticationPackage: session.AuthenticationPackage,

		Timestamp: session.Timestamp,

		Privileged: session.Privileged,

		Privileges: session.Privileges,

		MatchType: "authentication_id",

		Confidence: "high",
	}
}

func (s *Server) findProcessNetworkContext(
	process model.Process,
) []ProcessNetworkContext {

	processNetwork,
		found,
		err :=
		s.store.NetworkProcessByPID(
			process.PID,
		)

	if err != nil {

		fmt.Printf(
			"[web] load network analysis failed: %v\n",
			err,
		)

		return []ProcessNetworkContext{}
	}

	if !found {

		return []ProcessNetworkContext{}
	}

	result :=
		make(
			[]ProcessNetworkContext,
			0,
			len(processNetwork.Connections),
		)

	for _, connection := range processNetwork.Connections {

		result =
			append(
				result,
				ProcessNetworkContext{
					Protocol: connection.Protocol,

					Family: connection.Family,

					LocalAddress: connection.LocalAddress,

					LocalPort: connection.LocalPort,

					RemoteAddress: connection.RemoteAddress,

					RemotePort: connection.RemotePort,

					State: connection.State,

					External: networkConnectionInList(connection, processNetwork.ExternalConnections),

					Listener: networkConnectionInList(
						connection,
						processNetwork.Listeners,
					),

					PID: connection.PID,

					MatchType: "pid",
				},
			)
	}

	return result
}

func (s *Server) findProcessHistoricalContext(
	process model.Process,
) []ProcessHistoricalContext {

	historicalProcesses,
		err :=
		s.store.HistoricalProcessesByCurrentPID(
			process.PID,
		)

	if err != nil {

		return []ProcessHistoricalContext{}
	}

	result :=
		make(
			[]ProcessHistoricalContext,
			0,
			len(historicalProcesses),
		)

	for _, historical := range historicalProcesses {

		result =
			append(
				result,
				ProcessHistoricalContext{
					ID: historical.ID,

					PID: historical.PID,

					PPID: historical.ParentPID,

					ProcessName: historical.ProcessName,

					ProcessPath: historical.ProcessPath,

					CommandLine: historical.CommandLine,

					ParentProcessName: historical.ParentProcessName,

					CurrentProcessPath: historical.CurrentProcessPath,

					User: formatHistoricalUser(
						historical.Domain,
						historical.User,
					),

					LogonID: historical.LogonID,

					Timestamp: historical.Timestamp,

					TokenElevationType: historical.TokenElevationType,

					MandatoryLabel: historical.MandatoryLabel,

					MatchedLogin: historical.MatchedLogin,

					/*
					 * 关联仍来自 Historical Analyzer，
					 * 不是 Web 层根据 PID 推断。
					 */
					MatchType: "historical_analyzer_current_process",

					Confidence: "high",
				},
			)
	}

	return result
}

func (s *Server) findProcessPowerShellContext(
	process model.Process,
	historical []ProcessHistoricalContext,
) []ProcessPowerShellContext {

	/*
	 * process 参数目前保留，
	 * 维持现有函数签名。
	 *
	 * PowerShell 的关联依据仍然是
	 * RelatedHistoricalProcessID，
	 * 不是当前 PID。
	 */
	_ = process

	if len(historical) == 0 {

		return []ProcessPowerShellContext{}
	}

	result :=
		make(
			[]ProcessPowerShellContext,
			0,
		)

	seen :=
		make(
			map[string]struct{},
		)

	for _, historicalProcess := range historical {

		if historicalProcess.ID == "" {
			continue
		}

		blocks,
			err :=
			s.store.PowerShellByHistoricalProcessID(
				historicalProcess.ID,
			)

		if err != nil {
			continue
		}

		for _, block := range blocks {

			/*
			 * 防止相同 ScriptBlock 因异常数据
			 * 被重复加入。
			 */
			dedupKey :=
				block.ID

			if dedupKey == "" {

				dedupKey =
					block.ScriptBlockID
			}

			if dedupKey != "" {

				if _, exists :=
					seen[dedupKey]; exists {

					continue
				}

				seen[dedupKey] =
					struct{}{}
			}

			result =
				append(
					result,
					ProcessPowerShellContext{
						ScriptBlockID: block.ScriptBlockID,

						Timestamp: block.Timestamp,

						LastTimestamp: block.LastTimestamp,

						Path: block.Path,

						SHA256: block.ScriptSHA256,

						Complete: block.Complete,

						FragmentCount: block.FragmentCount,

						ScriptText: block.ScriptText,

						Indicators: nil,

						HistoricalProcessID: block.RelatedHistoricalProcessID,

						PID: block.ProcessID,

						User: block.User,

						LogonID: block.LogonID,

						Confidence: "high",

						MatchBasis: "historical_process_id",

						RelatedProcessName: block.RelatedProcessName,

						RelatedCommandLine: block.RelatedCommandLine,
					},
				)
		}
	}

	return result
}

func (s *Server) findProcessTimelineContext(
	process model.Process,
) []ProcessTimelineContext {

	events,
		err :=
		s.store.TimelineEventsByPID(
			process.PID,
		)

	if err != nil {

		return []ProcessTimelineContext{}
	}

	if len(events) == 0 {

		return []ProcessTimelineContext{}
	}

	limit :=
		len(events)

	if limit >
		maxProcessContextTimelineEvents {

		limit =
			maxProcessContextTimelineEvents
	}

	result :=
		make(
			[]ProcessTimelineContext,
			0,
			limit,
		)

	for index, event := range events {

		if index >=
			maxProcessContextTimelineEvents {

			break
		}

		result =
			append(
				result,
				ProcessTimelineContext{
					ID: event.ID,

					Timestamp: event.Timestamp,

					Category: event.Category,

					Type: event.Type,

					Description: event.Description,

					Severity: event.Severity,
				},
			)
	}

	return result
}

func sameNetworkConnection(
	left store.NetworkConnectionRecord,
	right store.NetworkConnectionRecord,
) bool {

	return left.PID ==
		right.PID &&
		strings.EqualFold(
			left.Protocol,
			right.Protocol,
		) &&
		strings.EqualFold(
			left.Family,
			right.Family,
		) &&
		left.LocalAddress ==
			right.LocalAddress &&
		left.LocalPort ==
			right.LocalPort &&
		left.RemoteAddress ==
			right.RemoteAddress &&
		left.RemotePort ==
			right.RemotePort &&
		strings.EqualFold(
			left.State,
			right.State,
		)
}

func networkConnectionInList(
	connection store.NetworkConnectionRecord,
	list []store.NetworkConnectionRecord,
) bool {

	for _, candidate := range list {

		if sameNetworkConnection(
			connection,
			candidate,
		) {

			return true
		}
	}

	return false
}

func webHistoricalProcessFromStore(
	process store.HistoricalProcessRecord,
) webHistoricalProcess {

	return webHistoricalProcess{
		ID: process.ID,

		Timestamp: process.Timestamp,

		PID: process.PID,

		ParentPID: process.ParentPID,

		ProcessName: process.ProcessName,

		ProcessPath: process.ProcessPath,

		CommandLine: process.CommandLine,

		ParentProcessName: process.ParentProcessName,

		User: process.User,

		Domain: process.Domain,

		LogonID: process.LogonID,

		TokenElevationType: process.TokenElevationType,

		MandatoryLabel: process.MandatoryLabel,

		MatchedLogin: process.MatchedLogin,

		CurrentProcess: process.CurrentProcess,

		CurrentProcessPath: process.CurrentProcessPath,
	}
}

func webHistoricalProcessesFromStore(
	processes []store.HistoricalProcessRecord,
) []webHistoricalProcess {

	result :=
		make(
			[]webHistoricalProcess,
			0,
			len(processes),
		)

	for _, process := range processes {

		result =
			append(
				result,
				webHistoricalProcessFromStore(
					process,
				),
			)
	}

	return result
}
