package local

import (
	"ir-toolkit/internal/store"
	"path/filepath"
)

func (s *CaseStore) ensureNetwork() error {

	s.networkOnce.Do(
		func() {

			s.networkProcessByPID =
				make(
					map[uint32]int,
				)

			s.networkByID =
				make(
					map[string]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"network_analysis.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.networkAnalysis,
				); err != nil {

				s.networkErr =
					err

				return
			}

			/*
				PID -> analyzer process network result
			*/
			for index, process := range s.networkAnalysis.Processes {

				s.networkProcessByPID[process.PID] =
					index
			}

			/*
				Flatten Connections + Listeners exactly once.

				注意这里使用 Store 内部类型，
				不再构造 Web 层网络 DTO。
			*/
			items :=
				make(
					[]NetworkItem,
					0,
				)

			for _, process := range s.networkAnalysis.Processes {

				/*
					External 只使用 Analyzer 已经产生的
					ExternalConnections membership。

					Store 不重新判断 IP 是否 external。
				*/
				externalKeys :=
					make(
						map[string]bool,
					)

				for _, connection := range process.ExternalConnections {

					key :=
						networkConnectionKey(
							process.PID,
							connection,
						)

					externalKeys[key] =
						true
				}

				for _, connection := range process.Connections {

					key :=
						networkConnectionKey(
							process.PID,
							connection,
						)

					item :=
						localNetworkItemFromConnection(
							process,
							connection,
							"connection",
							externalKeys[key],
						)

					items =
						append(
							items,
							item,
						)
				}

				for _, connection := range process.Listeners {

					item :=
						localNetworkItemFromConnection(
							process,
							connection,
							"listener",
							false,
						)

					items =
						append(
							items,
							item,
						)
				}
			}

			s.networkItems =
				items

			for index, item := range items {

				if item.ID == "" {
					continue
				}

				s.networkByID[item.ID] =
					index
			}
		},
	)

	return s.networkErr
}

func (s *CaseStore) NetworkAnalysis() (
	*store.NetworkAnalysisRecord,
	error,
) {

	if err :=
		s.ensureNetwork(); err != nil {

		return nil,
			err
	}

	return &s.networkAnalysis,
		nil
}

func (s *CaseStore) NetworkProcessByPID(
	pid uint32,
) (
	store.ProcessNetworkRecord,
	bool,
	error,
) {

	if err :=
		s.ensureNetwork(); err != nil {

		return store.ProcessNetworkRecord{},
			false,
			err
	}

	index,
		ok :=
		s.networkProcessByPID[pid]

	if !ok {

		return store.ProcessNetworkRecord{},
			false,
			nil
	}

	return s.networkAnalysis.Processes[index],
		true,
		nil
}

func (s *CaseStore) NetworkItems() (
	[]store.NetworkQueryItem,
	error,
) {

	if err :=
		s.ensureNetwork(); err != nil {

		return nil,
			err
	}

	items :=
		make(
			[]store.NetworkQueryItem,
			0,
			len(s.networkItems),
		)

	for _, item := range s.networkItems {

		items =
			append(
				items,
				networkQueryItemFromLocal(
					item,
				),
			)
	}

	return items,
		nil
}

func (s *CaseStore) NetworkItemByID(
	id string,
) (
	store.NetworkQueryItem,
	bool,
	error,
) {

	if err :=
		s.ensureNetwork(); err != nil {

		return store.NetworkQueryItem{},
			false,
			err
	}

	index,
		ok :=
		s.networkByID[id]

	if !ok {

		return store.NetworkQueryItem{},
			false,
			nil
	}

	return networkQueryItemFromLocal(
			s.networkItems[index],
		),
		true,
		nil
}
