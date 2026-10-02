package local

import (
	"fmt"
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"sort"
	"strconv"
	"strings"
)

func (s *CaseStore) searchProcessesLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureProcesses(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, process := range s.processes {

		pid :=
			strconv.FormatUint(
				uint64(process.PID),
				10,
			)

		ppid :=
			strconv.FormatUint(
				uint64(process.PPID),
				10,
			)

		sessionID :=
			strconv.FormatUint(
				uint64(process.SessionID),
				10,
			)

		if !searchContains(
			query,
			process.Name,
			process.Path,
			process.CommandLine,
			process.User,
			process.AuthenticationID,
			process.IntegrityLevel,
			process.SHA256,
			process.Signer,
			pid,
			ppid,
			sessionID,
		) {

			continue
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "process",

					ID: "process:" + pid,

					Title: firstNonEmpty(
						process.Name,
						"PID "+pid,
					),

					Subtitle: process.Path,

					Timestamp: process.StartTime,

					PID: process.PID,

					User: process.User,

					Object: firstNonEmpty(
						process.CommandLine,
						process.Path,
					),

					Match: "current process",

					Metadata: map[string]string{
						"ppid": ppid,

						"session_id": sessionID,

						"authentication_id": process.AuthenticationID,

						"integrity_level": process.IntegrityLevel,

						"sha256": process.SHA256,

						"signer": process.Signer,
					},
				},
			)
	}

	return results
}

func (s *CaseStore) searchLoginSessionsLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureLogin(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, session := range s.loginAnalysis.Sessions {

		if !searchContains(
			query,
			session.LogonID,
			session.User,
			session.Domain,
			session.SourceIP,
			session.SourcePort,
			session.Workstation,
			session.LogonTypeName,
			session.AuthenticationPackage,
			session.Privileges,

			strconv.FormatUint(
				uint64(session.LogonType),
				10,
			),
		) {

			continue
		}

		title :=
			session.User

		if session.Domain != "" {

			title =
				session.Domain +
					`\` +
					session.User
		}

		if title == "" {

			title =
				session.LogonID
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "login",

					ID: "login:" +
						normalizeLogonID(
							session.LogonID,
						),

					Title: title,

					Subtitle: session.LogonTypeName,

					Timestamp: session.Timestamp,

					User: title,

					IP: session.SourceIP,

					Object: session.LogonID,

					Match: "login session",

					Metadata: map[string]string{
						"logon_id": session.LogonID,

						"logon_type": strconv.FormatUint(
							uint64(
								session.LogonType,
							),
							10,
						),

						"logon_type_name": session.LogonTypeName,

						"workstation": session.Workstation,

						"authentication_package": session.AuthenticationPackage,

						"privileges": session.Privileges,

						"process_count": strconv.FormatUint(
							uint64(
								session.ProcessCount,
							),
							10,
						),

						"processes_with_network": strconv.FormatUint(
							uint64(
								session.ProcessesWithNetwork,
							),
							10,
						),

						"processes_with_external_network": strconv.FormatUint(
							uint64(
								session.ProcessesWithExternalNetwork,
							),
							10,
						),
					},
				},
			)
	}

	return results
}

func (s *CaseStore) searchNetworkLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureNetwork(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, item := range s.networkItems {

		/*
			保持原 Global Search 行为：
			只搜索 connection，不额外加入 listener。
		*/
		if item.Kind !=
			"connection" {

			continue
		}

		pid :=
			strconv.FormatUint(
				uint64(item.PID),
				10,
			)

		localPort :=
			strconv.FormatUint(
				uint64(item.LocalPort),
				10,
			)

		remotePort :=
			strconv.FormatUint(
				uint64(item.RemotePort),
				10,
			)

		if !searchContains(
			query,
			item.ID,
			pid,
			item.ProcessName,
			item.ProcessPath,
			item.User,
			item.AuthenticationID,
			item.Protocol,
			item.Family,
			item.LocalAddress,
			localPort,
			item.RemoteAddress,
			remotePort,
			item.State,
			item.Kind,
		) {

			continue
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "network",

					/*
						直接使用 canonical Network Evidence ID。
					*/
					ID: item.ID,

					Title: firstNonEmpty(
						item.ProcessName,
						"PID "+pid,
					),

					Subtitle: fmt.Sprintf(
						"%s %s:%d → %s:%d",
						item.Protocol,
						item.LocalAddress,
						item.LocalPort,
						item.RemoteAddress,
						item.RemotePort,
					),

					PID: item.PID,

					User: item.User,

					IP: item.RemoteAddress,

					Object: item.ProcessPath,

					Match: "network connection",

					Metadata: map[string]string{
						"authentication_id": item.AuthenticationID,

						"family": item.Family,

						"state": item.State,

						"kind": item.Kind,

						"external": strconv.FormatBool(
							item.External,
						),

						"local_address": item.LocalAddress,

						"local_port": localPort,

						"remote_address": item.RemoteAddress,

						"remote_port": remotePort,
					},
				},
			)
	}

	return results
}

func (s *CaseStore) SearchInvestigation(
	options store.InvestigationSearchOptions,
) (
	store.InvestigationSearchStoreResult,
	error,
) {

	result :=
		store.InvestigationSearchStoreResult{
			ByType: make(
				map[string]uint32,
			),

			Items: make(
				[]store.InvestigationSearchItem,
				0,
			),
		}

	if strings.TrimSpace(
		options.Query,
	) == "" {

		return result,
			nil
	}

	appendItems :=
		func(
			items []store.InvestigationSearchItem,
		) {

			for _, item := range items {

				result.ByType[item.Type]++

				result.Items =
					append(
						result.Items,
						item,
					)
			}
		}

	// ------------------------------------------
	// Current Process
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"process",
	) {

		appendItems(
			s.searchProcessesLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Login
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"login",
	) {

		appendItems(
			s.searchLoginSessionsLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Network
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"network",
	) {

		appendItems(
			s.searchNetworkLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Historical Process
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"historical_process",
	) {

		appendItems(
			s.searchHistoricalProcessesLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// PowerShell
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"powershell",
	) {

		appendItems(
			s.searchPowerShellLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Windows Event
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"windows_event",
	) {

		appendItems(
			s.searchWindowsEventsLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// IOC
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"ioc",
	) {

		appendItems(
			s.searchIOCMatchesLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// File
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"file",
	) {

		appendItems(
			s.searchFilesLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Persistence
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"persistence",
	) {

		appendItems(
			s.searchPersistenceLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Timeline
	// ------------------------------------------

	if searchTypeEnabled(
		options.Types,
		"timeline",
	) {

		appendItems(
			s.searchTimelineLocal(
				options.Query,
			),
		)
	}

	// ------------------------------------------
	// Correlation
	//
	// 一个查询同时产生：
	//
	// correlation_node
	// correlation_edge
	// ------------------------------------------

	if len(options.Types) == 0 ||
		searchTypeEnabled(
			options.Types,
			"correlation_node",
		) ||
		searchTypeEnabled(
			options.Types,
			"correlation_edge",
		) {

		correlationItems :=
			s.searchCorrelationLocal(
				options.Query,
			)

		for _, item := range correlationItems {

			if len(options.Types) != 0 &&
				!searchTypeEnabled(
					options.Types,
					item.Type,
				) {

				continue
			}

			result.ByType[item.Type]++

			result.Items =
				append(
					result.Items,
					item,
				)
		}
	}

	// ------------------------------------------
	// Global Sort
	//
	// Timestamp DESC。
	// Zero timestamp 放最后。
	// ------------------------------------------

	sort.SliceStable(
		result.Items,
		func(i, j int) bool {

			left :=
				result.Items[i].
					Timestamp

			right :=
				result.Items[j].
					Timestamp

			if left.IsZero() &&
				right.IsZero() {

				return false
			}

			if left.IsZero() {
				return false
			}

			if right.IsZero() {
				return true
			}

			return left.After(
				right,
			)
		},
	)

	/*
		Total 必须在 Limit 之前计算。
	*/
	result.Total =
		uint32(
			len(result.Items),
		)

	// ------------------------------------------
	// Limit
	// ------------------------------------------

	limit :=
		normalizeQueryLimit(
			options.Limit,
		)

	if len(result.Items) >
		limit {

		result.Items =
			result.Items[:limit]
	}

	return result,
		nil
}

func (s *CaseStore) searchHistoricalProcessesLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureHistoricalProcesses(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, process := range s.historicalAnalysis.Processes {

		pid :=
			strconv.FormatUint(
				uint64(process.PID),
				10,
			)

		ppid :=
			strconv.FormatUint(
				uint64(process.ParentPID),
				10,
			)

		if !searchContains(
			query,
			process.ID,
			process.ProcessName,
			process.ProcessPath,
			process.CommandLine,
			process.ParentProcessName,
			process.User,
			process.Domain,
			process.LogonID,
			process.TokenElevationType,
			process.MandatoryLabel,
			process.CurrentProcessPath,
			pid,
			ppid,
		) {

			continue
		}

		user :=
			formatHistoricalUser(
				process.Domain,
				process.User,
			)

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "historical_process",

					ID: process.ID,

					Title: firstNonEmpty(
						process.ProcessName,
						"PID "+pid,
					),

					Subtitle: process.ProcessPath,

					Timestamp: process.Timestamp,

					PID: process.PID,

					User: user,

					Object: firstNonEmpty(
						process.CommandLine,
						process.ProcessPath,
					),

					Match: "historical process",

					Metadata: map[string]string{
						"ppid": ppid,

						"logon_id": process.LogonID,

						"parent_process_name": process.ParentProcessName,

						"token_elevation_type": process.TokenElevationType,

						"mandatory_label": process.MandatoryLabel,

						"current_process": strconv.FormatBool(
							process.CurrentProcess,
						),

						"current_process_path": process.CurrentProcessPath,

						"matched_login": strconv.FormatBool(
							process.MatchedLogin,
						),
					},
				},
			)
	}

	return results
}

func (s *CaseStore) searchPowerShellLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensurePowerShell(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, block := range s.powershellAnalysis.ScriptBlocks {

		pid :=
			strconv.FormatUint(
				uint64(block.ProcessID),
				10,
			)

		if !searchContains(
			query,
			block.ID,
			block.ScriptBlockID,
			block.Path,
			block.ScriptText,
			block.ScriptSHA256,
			block.RelatedHistoricalProcessID,
			block.RelatedProcessName,
			block.RelatedCommandLine,
			block.User,
			block.LogonID,
			pid,
		) {

			continue
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "powershell",

					ID: block.ID,

					Title: "PowerShell ScriptBlock",

					Subtitle: block.Path,

					Timestamp: block.Timestamp,

					PID: block.ProcessID,

					User: block.User,

					Object: firstNonEmpty(
						block.ScriptBlockID,
						block.Path,
					),

					Match: "powershell",

					Metadata: map[string]string{
						"script_block_id": block.ScriptBlockID,

						"script_sha256": block.ScriptSHA256,

						"historical_process_id": block.RelatedHistoricalProcessID,

						"related_process_name": block.RelatedProcessName,

						"related_command_line": block.RelatedCommandLine,

						"logon_id": block.LogonID,

						"complete": strconv.FormatBool(
							block.Complete,
						),

						"fragment_count": strconv.FormatUint(
							uint64(
								block.FragmentCount,
							),
							10,
						),
					},
				},
			)
	}

	return results
}

func (s *CaseStore) searchWindowsEventsLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureWindowsEvents(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, activity := range s.windowsEventAnalysis.Activities {

		values :=
			[]string{
				activity.ID,
				activity.Type,
				activity.Category,
				activity.Severity,
				activity.DefinitionID,
				activity.Channel,

				strconv.FormatUint(
					uint64(activity.EventID),
					10,
				),

				strconv.FormatUint(
					activity.RecordID,
					10,
				),

				activity.User,
				activity.SourceIP,
				activity.SessionID,

				strconv.FormatUint(
					uint64(activity.ProcessID),
					10,
				),

				activity.Process,
				activity.Object,
				activity.Description,
			}

		values =
			append(
				values,
				activity.Reasons...,
			)

		values =
			append(
				values,
				activity.RelatedIDs...,
			)

		for key, value := range activity.Metadata {

			values =
				append(
					values,
					key,
					value,
				)
		}

		if !searchContains(
			query,
			values...,
		) {

			continue
		}

		metadata :=
			make(
				map[string]string,
				len(activity.Metadata)+12,
			)

		for key, value := range activity.Metadata {

			metadata[key] =
				value
		}

		metadata["category"] =
			activity.Category

		metadata["severity"] =
			activity.Severity

		metadata["definition_id"] =
			activity.DefinitionID

		metadata["channel"] =
			activity.Channel

		metadata["event_id"] =
			strconv.FormatUint(
				uint64(activity.EventID),
				10,
			)

		metadata["record_id"] =
			strconv.FormatUint(
				activity.RecordID,
				10,
			)

		metadata["source_ip"] =
			activity.SourceIP

		metadata["session_id"] =
			activity.SessionID

		metadata["process_id"] =
			strconv.FormatUint(
				uint64(activity.ProcessID),
				10,
			)

		metadata["process"] =
			activity.Process

		metadata["description"] =
			activity.Description

		if len(activity.Reasons) > 0 {

			metadata["reasons"] =
				strings.Join(
					activity.Reasons,
					" | ",
				)
		}

		if len(activity.RelatedIDs) > 0 {

			metadata["related_ids"] =
				strings.Join(
					activity.RelatedIDs,
					", ",
				)
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "windows_event",

					ID: activity.ID,

					Title: firstNonEmpty(
						activity.Type,
						"Windows Event",
					),

					Subtitle: activity.Channel,

					Timestamp: activity.Timestamp,

					PID: activity.ProcessID,

					User: activity.User,

					IP: activity.SourceIP,

					Object: activity.Object,

					Match: "windows event",

					Metadata: metadata,
				},
			)
	}

	return results
}

func (s *CaseStore) searchIOCMatchesLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureIOC(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for index, match := range s.iocScanResult.Matches {

		pid :=
			strconv.FormatUint(
				uint64(match.PID),
				10,
			)

		remotePort :=
			strconv.FormatUint(
				uint64(match.RemotePort),
				10,
			)

		if !searchContains(
			query,
			match.IOCType,
			match.IOCValue,
			match.Description,
			match.MatchType,
			match.Source,
			match.Object,
			pid,
			match.Process,
			match.Path,
			match.SHA256,
			match.RemoteAddress,
			remotePort,
			match.CommandLine,
			match.PersistenceType,
			match.PersistenceName,
			match.RelatedID,
		) {

			continue
		}

		resultID :=
			fmt.Sprintf(
				"ioc-match:%d",
				index,
			)

		title :=
			match.IOCType

		if match.IOCValue != "" {

			if title != "" {
				title += ": "
			}

			title +=
				match.IOCValue
		}

		if title == "" {

			title =
				"IOC Match"
		}

		subtitle :=
			match.MatchType

		if match.Source != "" {

			if subtitle != "" {
				subtitle += " · "
			}

			subtitle +=
				match.Source
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "ioc",

					ID: resultID,

					Title: title,

					Subtitle: subtitle,

					PID: match.PID,

					IP: match.RemoteAddress,

					Object: firstNonEmpty(
						match.Object,
						match.Path,
						match.Process,
						match.CommandLine,
						match.IOCValue,
					),

					Match: "ioc match",

					Metadata: map[string]string{
						"ioc_type": match.IOCType,

						"ioc_value": match.IOCValue,

						"description": match.Description,

						"match_type": match.MatchType,

						"source": match.Source,

						"object": match.Object,

						"pid": pid,

						"process": match.Process,

						"path": match.Path,

						"sha256": match.SHA256,

						"remote_address": match.RemoteAddress,

						"remote_port": remotePort,

						"command_line": match.CommandLine,

						"persistence_type": match.PersistenceType,

						"persistence_name": match.PersistenceName,

						"related_id": match.RelatedID,
					},
				},
			)
	}

	return results
}

func (s *CaseStore) searchFilesLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureFiles(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, file := range s.fileSnapshot.Files {

		finding,
			hasFinding :=
			s.fileFindingByPath[normalizeFileEvidencePath(
				file.Path,
			)]

		fileMatched :=
			fileEvidenceMatchesQuery(
				file,
				query,
			)

		findingMatched :=
			false

		if hasFinding {

			values :=
				[]string{
					finding.ID,
					finding.Severity,
					finding.Title,
					finding.Path,
					finding.SHA256,
					strconv.Itoa(
						finding.Score,
					),
				}

			values =
				append(
					values,
					finding.Reasons...,
				)

			values =
				append(
					values,
					finding.RelatedProcesses...,
				)

			values =
				append(
					values,
					finding.Persistence...,
				)

			findingMatched =
				searchContains(
					query,
					values...,
				)
		}

		if !fileMatched &&
			!findingMatched {

			continue
		}

		metadata :=
			map[string]string{
				"path": file.Path,

				"name": file.Name,

				"extension": file.Extension,

				"owner": file.Owner,

				"sha256": file.SHA256,

				"source": file.Source,

				"executable": strconv.FormatBool(
					file.Executable,
				),
			}

		if file.ZoneIdentifier != "" {

			metadata["zone_identifier"] =
				file.ZoneIdentifier
		}

		if hasFinding {

			metadata["finding_id"] =
				finding.ID

			metadata["finding_severity"] =
				finding.Severity

			metadata["finding_title"] =
				finding.Title

			metadata["finding_score"] =
				strconv.Itoa(
					finding.Score,
				)
		}

		match :=
			"file evidence"

		if hasFinding {

			switch {

			case fileMatched &&
				findingMatched:

				match =
					"file evidence and analysis finding"

			case findingMatched:

				match =
					"analysis finding"

			default:

				match =
					"file evidence with analysis finding"
			}
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "file",

					ID: "file:" +
						normalizeFileEvidencePath(
							file.Path,
						),

					Title: firstNonEmpty(
						file.Name,
						file.Path,
					),

					Subtitle: file.Path,

					Timestamp: file.ModifiedAt,

					Object: file.Path,

					Match: match,

					Metadata: metadata,
				},
			)
	}

	return results
}

func (s *CaseStore) searchTimelineLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureTimeline(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, event := range s.timeline.Events {

		if !timelineEventContains(
			event,
			query,
		) {

			continue
		}

		pid :=
			strconv.FormatUint(
				uint64(event.PID),
				10,
			)

		ppid :=
			strconv.FormatUint(
				uint64(event.PPID),
				10,
			)

		metadata :=
			make(
				map[string]string,
				len(event.Metadata)+10,
			)

		for key, value := range event.Metadata {

			metadata[key] =
				value
		}

		metadata["type"] =
			event.Type

		metadata["category"] =
			event.Category

		metadata["severity"] =
			event.Severity

		metadata["host"] =
			event.Host

		metadata["pid"] =
			pid

		metadata["ppid"] =
			ppid

		metadata["process"] =
			event.Process

		metadata["logon_id"] =
			event.LogonID

		metadata["description"] =
			event.Description

		if len(event.RelatedIDs) > 0 {

			metadata["related_ids"] =
				strings.Join(
					event.RelatedIDs,
					", ",
				)
		}

		title :=
			event.Type

		if title == "" {

			title =
				"Timeline Event"
		}

		subtitle :=
			event.Category

		if event.Process != "" {

			if subtitle != "" {
				subtitle += " · "
			}

			subtitle +=
				event.Process
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "timeline",

					ID: event.ID,

					Title: title,

					Subtitle: subtitle,

					Timestamp: event.Timestamp,

					PID: event.PID,

					User: event.User,

					IP: event.SourceIP,

					Object: firstNonEmpty(
						event.Object,
						event.Process,
						event.LogonID,
						event.Description,
					),

					Match: "timeline event",

					Metadata: metadata,
				},
			)
	}

	return results
}

func (s *CaseStore) searchPersistenceLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensurePersistence(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	for _, item := range s.persistenceItems {

		var finding *model.PersistenceFinding

		if item.FindingID != "" {

			if value, ok :=
				s.persistenceFindingByID[item.FindingID]; ok {

				copy :=
					value

				finding =
					&copy
			}
		}

		if !persistenceStoreItemMatches(
			item,
			finding,
			query,
		) {

			continue
		}

		metadata :=
			map[string]string{
				"type": item.Type,

				"name": item.Name,

				"command": item.Command,
			}

		match :=
			"persistence evidence"

		if finding != nil {

			match =
				"persistence evidence with analysis finding"

			metadata["finding_id"] =
				finding.ID

			metadata["finding_severity"] =
				finding.Severity
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "persistence",

					ID: item.ID,

					Title: firstNonEmpty(
						item.Title,
						item.Name,
					),

					Subtitle: item.Type,

					Timestamp: item.Timestamp,

					PID: item.PID,

					User: item.User,

					Object: item.Object,

					Match: match,

					Metadata: metadata,
				},
			)
	}

	return results
}

func (s *CaseStore) searchCorrelationLocal(
	query string,
) []store.InvestigationSearchItem {

	if err :=
		s.ensureCorrelation(); err != nil {

		return nil
	}

	results :=
		make(
			[]store.InvestigationSearchItem,
			0,
		)

	// ------------------------------------------
	// Nodes
	// ------------------------------------------

	for _, node := range s.correlationAnalysis.Nodes {

		values :=
			[]string{
				node.ID,
				node.Type,
				node.Label,
				node.Object,
			}

		for key, value := range node.Metadata {

			values =
				append(
					values,
					key,
					value,
				)
		}

		if !searchContains(
			query,
			values...,
		) {

			continue
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "correlation_node",

					ID: node.ID,

					Title: firstNonEmpty(
						node.Label,
						node.Object,
						node.ID,
					),

					Subtitle: node.Type,

					Timestamp: node.Timestamp,

					PID: node.PID,

					User: node.User,

					Object: node.Object,

					Match: "correlation node",

					Metadata: node.Metadata,
				},
			)
	}

	// ------------------------------------------
	// Edges
	// ------------------------------------------

	for _, edge := range s.correlationAnalysis.Edges {

		values :=
			[]string{
				edge.ID,
				edge.From,
				edge.To,
				edge.Type,
				edge.Confidence,

				strconv.Itoa(
					edge.Score,
				),
			}

		for _, basis := range edge.Basis {

			values =
				append(
					values,
					basis.Type,
					basis.Value,
					basis.Description,
				)
		}

		if !searchContains(
			query,
			values...,
		) {

			continue
		}

		match :=
			"correlation edge"

		if edge.Confidence != "" {

			match =
				edge.Confidence +
					" confidence"
		}

		results =
			append(
				results,
				store.InvestigationSearchItem{
					Type: "correlation_edge",

					ID: edge.ID,

					Title: firstNonEmpty(
						edge.Type,
						"Correlation Edge",
					),

					Subtitle: edge.From +
						" → " +
						edge.To,

					Timestamp: edge.Timestamp,

					Match: match,

					Metadata: map[string]string{
						"from": edge.From,

						"to": edge.To,

						"type": edge.Type,

						"confidence": edge.Confidence,

						"score": strconv.Itoa(
							edge.Score,
						),
					},
				},
			)
	}

	return results
}

func firstNonEmpty(
	values ...string,
) string {

	for _, value := range values {

		value =
			strings.TrimSpace(
				value,
			)

		if value != "" {
			return value
		}
	}

	return ""
}

func formatHistoricalUser(
	domain string,
	user string,
) string {

	domain =
		strings.TrimSpace(
			domain,
		)

	user =
		strings.TrimSpace(
			user,
		)

	if user == "" ||
		user == "-" {

		return ""
	}

	if domain == "" ||
		domain == "-" {

		return user
	}

	return domain +
		`\` +
		user
}
