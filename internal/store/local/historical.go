package local

import (
	"ir-toolkit/internal/store"
	"path/filepath"
)

func (s *CaseStore) ensureHistoricalProcesses() error {

	s.historicalOnce.Do(
		func() {

			s.historicalByID =
				make(
					map[string]int,
				)

			s.historicalByCurrentPID =
				make(
					map[uint32][]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"process_history_analysis.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.historicalAnalysis,
				); err != nil {

				s.historicalErr =
					err

				return
			}

			for index, process := range s.historicalAnalysis.Processes {

				if process.ID != "" {

					s.historicalByID[process.ID] =
						index
				}

				/*
				 * 只有 Analyzer 已确认：
				 *
				 * CurrentProcess == true
				 *
				 * 才进入 PID → Historical 索引。
				 *
				 * 不能仅凭相同 PID 关联历史进程。
				 */
				if process.CurrentProcess {

					s.historicalByCurrentPID[process.PID] =
						append(
							s.historicalByCurrentPID[process.PID],
							index,
						)
				}
			}
		},
	)

	return s.historicalErr
}

func (s *CaseStore) HistoricalProcesses() (
	[]store.HistoricalProcessRecord,
	error,
) {

	if err :=
		s.ensureHistoricalProcesses(); err != nil {

		return nil,
			err
	}

	return s.historicalAnalysis.Processes,
		nil
}

func (s *CaseStore) HistoricalProcessByID(
	id string,
) (
	store.HistoricalProcessRecord,
	bool,
	error,
) {

	if err :=
		s.ensureHistoricalProcesses(); err != nil {

		return store.HistoricalProcessRecord{},
			false,
			err
	}

	index,
		ok :=
		s.historicalByID[id]

	if !ok {

		return store.HistoricalProcessRecord{},
			false,
			nil
	}

	return s.historicalAnalysis.Processes[index],
		true,
		nil
}

func (s *CaseStore) HistoricalProcessesByCurrentPID(
	pid uint32,
) (
	[]store.HistoricalProcessRecord,
	error,
) {

	if err :=
		s.ensureHistoricalProcesses(); err != nil {

		return nil,
			err
	}

	indexes :=
		s.historicalByCurrentPID[pid]

	if len(indexes) == 0 {

		return []store.HistoricalProcessRecord{},
			nil
	}

	result :=
		make(
			[]store.HistoricalProcessRecord,
			0,
			len(indexes),
		)

	for _, index := range indexes {

		result =
			append(
				result,
				s.historicalAnalysis.Processes[index],
			)
	}

	return result,
		nil
}
