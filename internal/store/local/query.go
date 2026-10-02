package local

import (
	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
	"sort"
	"strconv"
	"strings"
)

func (s *CaseStore) QueryProcesses(
	options store.ProcessQueryOptions,
) (
	store.QueryResult[model.Process],
	error,
) {

	if err :=
		s.ensureProcesses(); err != nil {

		return store.QueryResult[model.Process]{},
			err
	}

	filtered :=
		make(
			[]model.Process,
			0,
			len(s.processes),
		)

	for _, process := range s.processes {

		if options.PID != 0 &&
			process.PID != options.PID {

			continue
		}

		if options.User != "" &&
			!containsFold(
				process.User,
				options.User,
			) {

			continue
		}

		if options.Query != "" &&
			!processMatchesSearch(
				process,
				options.Query,
			) {

			continue
		}

		filtered =
			append(
				filtered,
				process,
			)
	}

	sort.SliceStable(
		filtered,
		func(i, j int) bool {

			return filtered[i].PID <
				filtered[j].PID
		},
	)

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	processes :=
		append(
			[]model.Process(nil),
			filtered[page.Offset:end]...,
		)

	return store.QueryResult[model.Process]{
			Total: uint32(total),

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Items: processes,
		},
		nil
}

func (s *CaseStore) QueryLogins(
	options store.LoginQueryOptions,
) (
	store.QueryResult[model.LoginSessionAnalysis],
	error,
) {

	if err :=
		s.ensureLogin(); err != nil {

		return store.QueryResult[model.LoginSessionAnalysis]{},
			err
	}

	filtered :=
		make(
			[]model.LoginSessionAnalysis,
			0,
			len(s.loginAnalysis.Sessions),
		)

	for _, session := range s.loginAnalysis.Sessions {

		if options.User != "" &&
			!searchContains(
				options.User,
				session.User,
				session.Domain,
			) {

			continue
		}

		if options.IP != "" &&
			!searchContains(
				options.IP,
				session.SourceIP,
			) {

			continue
		}

		if options.LogonType != "" &&
			!searchContains(
				options.LogonType,
				session.LogonTypeName,
				strconv.FormatUint(
					uint64(
						session.LogonType,
					),
					10,
				),
			) {

			continue
		}

		if options.Query != "" &&
			!searchContains(
				options.Query,
				session.LogonID,
				session.User,
				session.Domain,
				session.SourceIP,
				session.SourcePort,
				session.Workstation,
				session.LogonTypeName,
				session.AuthenticationPackage,
				session.Privileges,
			) {

			continue
		}

		filtered =
			append(
				filtered,
				session,
			)
	}

	sort.SliceStable(
		filtered,
		func(i, j int) bool {

			return filtered[i].
				Timestamp.
				After(
					filtered[j].
						Timestamp,
				)
		},
	)

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	sessions :=
		append(
			[]model.LoginSessionAnalysis(nil),
			filtered[page.Offset:end]...,
		)

	return store.QueryResult[model.LoginSessionAnalysis]{
			Total: uint32(total),

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Items: sessions,
		},
		nil
}

func (s *CaseStore) QueryNetwork(
	options store.NetworkQueryOptions,
) (
	store.QueryResult[store.NetworkQueryItem],
	error,
) {

	if err :=
		s.ensureNetwork(); err != nil {

		return store.QueryResult[store.NetworkQueryItem]{},
			err
	}

	filtered :=
		make(
			[]store.NetworkQueryItem,
			0,
			len(s.networkItems),
		)

	for _, item := range s.networkItems {

		if options.PID != 0 &&
			item.PID !=
				options.PID {

			continue
		}

		if options.IP != "" &&
			!searchContains(
				options.IP,
				item.LocalAddress,
				item.RemoteAddress,
			) {

			continue
		}

		if options.State != "" &&
			!searchContains(
				options.State,
				item.State,
			) {

			continue
		}

		if options.External != nil &&
			item.External !=
				*options.External {

			continue
		}

		if options.Query != "" &&
			!searchContains(
				options.Query,
				item.ID,

				strconv.FormatUint(
					uint64(
						item.PID,
					),
					10,
				),

				item.ProcessName,
				item.ProcessPath,
				item.User,
				item.AuthenticationID,
				item.Protocol,
				item.Family,
				item.LocalAddress,

				strconv.FormatUint(
					uint64(
						item.LocalPort,
					),
					10,
				),

				item.RemoteAddress,

				strconv.FormatUint(
					uint64(
						item.RemotePort,
					),
					10,
				),

				item.State,
				item.Kind,
			) {

			continue
		}

		filtered =
			append(
				filtered,
				networkQueryItemFromLocal(
					item,
				),
			)
	}

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	items :=
		append(
			[]store.NetworkQueryItem(nil),
			filtered[page.Offset:end]...,
		)

	return store.QueryResult[store.NetworkQueryItem]{
			Total: uint32(total),

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Items: items,
		},
		nil
}

func (s *CaseStore) QueryFiles(
	options store.FileQueryOptions,
) (
	store.QueryResult[store.FileQueryItem],
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return store.QueryResult[store.FileQueryItem]{},
			err
	}

	filtered :=
		make(
			[]store.FileQueryItem,
			0,
			len(s.fileSnapshot.Files),
		)

	for _, file := range s.fileSnapshot.Files {

		key :=
			normalizeFileEvidencePath(
				file.Path,
			)

		finding,
			hasFinding :=
			s.fileFindingByPath[key]

		// ------------------------------------------
		// Owner
		// ------------------------------------------

		if options.Owner != "" &&
			!containsFold(
				file.Owner,
				options.Owner,
			) {

			continue
		}

		// ------------------------------------------
		// Extension
		// ------------------------------------------

		if options.Extension != "" &&
			!strings.EqualFold(
				file.Extension,
				options.Extension,
			) {

			continue
		}

		// ------------------------------------------
		// Executable
		// ------------------------------------------

		if options.Executable != nil &&
			file.Executable !=
				*options.Executable {

			continue
		}

		// ------------------------------------------
		// Finding
		// ------------------------------------------

		if options.Finding != nil &&
			hasFinding !=
				*options.Finding {

			continue
		}

		// ------------------------------------------
		// Full-text query
		// ------------------------------------------

		if options.Query != "" {

			fileMatched :=
				fileEvidenceMatchesQuery(
					file,
					options.Query,
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
						options.Query,
						values...,
					)
			}

			if !fileMatched &&
				!findingMatched {

				continue
			}
		}

		// ------------------------------------------
		// DTO
		// ------------------------------------------

		item :=
			store.FileQueryItem{
				Evidence: file,
			}

		if hasFinding {

			findingCopy :=
				finding

			item.Finding =
				&findingCopy
		}

		filtered =
			append(
				filtered,
				item,
			)
	}

	// ------------------------------------------
	// Sort
	//
	// 保持原 /api/files 行为：
	// ModifiedAt DESC，零时间放最后。
	// ------------------------------------------

	sort.SliceStable(
		filtered,
		func(i, j int) bool {

			left :=
				filtered[i].
					Evidence.
					ModifiedAt

			right :=
				filtered[j].
					Evidence.
					ModifiedAt

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

	// ------------------------------------------
	// Pagination
	// ------------------------------------------

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	items :=
		append(
			[]store.FileQueryItem(nil),
			filtered[page.Offset:end]...,
		)

	return store.QueryResult[store.FileQueryItem]{
			Total: uint32(total),

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Items: items,
		},
		nil
}

func (s *CaseStore) QueryPersistence(
	options store.PersistenceQueryOptions,
) (
	store.QueryResult[store.PersistenceQueryItem],
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return store.QueryResult[store.PersistenceQueryItem]{},
			err
	}

	filtered :=
		make(
			[]store.PersistenceQueryItem,
			0,
			len(s.persistenceItems),
		)

	for _, item := range s.persistenceItems {

		if options.Type != "" &&
			!strings.EqualFold(
				item.Type,
				options.Type,
			) {

			continue
		}

		if options.User != "" &&
			!containsFold(
				item.User,
				options.User,
			) {

			continue
		}

		if options.Finding != nil &&
			item.HasFinding !=
				*options.Finding {

			continue
		}

		var finding *model.PersistenceFinding

		if item.FindingID != "" {

			if value, ok :=
				s.persistenceFindingByID[item.FindingID]; ok {

				findingCopy :=
					value

				finding =
					&findingCopy
			}
		}

		if options.Query != "" &&
			!persistenceStoreItemMatches(
				item,
				finding,
				options.Query,
			) {

			continue
		}

		filtered =
			append(
				filtered,
				s.persistenceQueryItemFromLocal(
					item,
				),
			)
	}

	sort.SliceStable(
		filtered,
		func(i, j int) bool {

			leftHasFinding :=
				filtered[i].Finding != nil

			rightHasFinding :=
				filtered[j].Finding != nil

			if leftHasFinding !=
				rightHasFinding {

				return leftHasFinding
			}

			left :=
				filtered[i].
					Timestamp

			right :=
				filtered[j].
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

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	items :=
		append(
			[]store.PersistenceQueryItem(nil),
			filtered[page.Offset:end]...,
		)

	return store.QueryResult[store.PersistenceQueryItem]{
			Total: uint32(total),

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Items: items,
		},
		nil
}

func (s *CaseStore) QueryTimeline(
	options store.TimelineQueryOptions,
) (
	store.TimelineQueryResult,
	error,
) {

	if err :=
		s.ensureTimeline(); err != nil {

		return store.TimelineQueryResult{},
			err
	}

	events :=
		append(
			[]model.TimelineEvent(nil),
			s.timeline.Events...,
		)

	sort.SliceStable(
		events,
		func(i, j int) bool {

			left :=
				events[i].
					Timestamp

			right :=
				events[j].
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

			if options.Order ==
				"desc" {

				return left.After(
					right,
				)
			}

			return left.Before(
				right,
			)
		},
	)

	filtered :=
		make(
			[]model.TimelineEvent,
			0,
			len(events),
		)

	categoryCounts :=
		make(
			map[string]uint32,
		)

	for _, event := range events {

		if timelineEventMatchesOptionsWithoutCategory(
			event,
			options,
		) {

			category :=
				event.Category

			if category == "" {

				category =
					"other"
			}

			categoryCounts[category]++
		}

		if !timelineEventMatchesOptions(
			event,
			options,
		) {

			continue
		}

		filtered =
			append(
				filtered,
				event,
			)
	}

	total :=
		len(filtered)

	page :=
		normalizeQueryPage(
			options.Page.Offset,
			options.Page.Limit,
			total,
		)

	end :=
		queryPageEnd(
			page,
			total,
		)

	pageEvents :=
		append(
			[]model.TimelineEvent(nil),
			filtered[page.Offset:end]...,
		)

	return store.TimelineQueryResult{
			Total: uint32(total),

			CategoryCounts: categoryCounts,

			Page: buildQueryPageResult(
				page,
				end,
				total,
			),

			Events: pageEvents,
		},
		nil
}

func persistenceStoreItemMatches(
	item PersistenceItem,
	finding *model.PersistenceFinding,
	query string,
) bool {

	if query == "" {
		return true
	}

	values :=
		[]string{
			item.ID,
			item.Type,
			item.Name,
			item.Title,
			item.Command,
			item.User,
			item.Object,

			strconv.FormatUint(
				uint64(item.PID),
				10,
			),
		}

	if finding != nil {

		values =
			append(
				values,
				finding.ID,
				finding.Severity,
				finding.Title,
				finding.Type,
				finding.Name,
				finding.Command,
				finding.ExecutablePath,
				finding.User,

				strconv.Itoa(
					finding.Score,
				),
			)

		values =
			append(
				values,
				finding.Reasons...,
			)
	}

	return searchContains(
		query,
		values...,
	)
}

func networkQueryItemFromLocal(
	item NetworkItem,
) store.NetworkQueryItem {

	return store.NetworkQueryItem{
		ID: item.ID,

		PID: item.PID,

		ProcessName: item.ProcessName,

		ProcessPath: item.ProcessPath,

		User: item.User,

		AuthenticationID: item.AuthenticationID,

		Protocol: item.Protocol,

		Family: item.Family,

		LocalAddress: item.LocalAddress,

		LocalPort: item.LocalPort,

		RemoteAddress: item.RemoteAddress,

		RemotePort: item.RemotePort,

		State: item.State,

		Kind: item.Kind,

		External: item.External,
	}
}

func (s *CaseStore) persistenceQueryItemFromLocal(
	item PersistenceItem,
) store.PersistenceQueryItem {

	result :=
		store.PersistenceQueryItem{
			ID: item.ID,

			Type: item.Type,

			Name: item.Name,

			Title: item.Title,

			Command: item.Command,

			User: item.User,

			Object: item.Object,

			Timestamp: item.Timestamp,

			PID: item.PID,
		}

	if item.FindingID != "" {

		if finding, ok :=
			s.persistenceFindingByID[item.FindingID]; ok {

			findingCopy :=
				finding

			result.Finding =
				&findingCopy
		}
	}

	return result
}
