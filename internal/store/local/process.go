package local

import (
	"path/filepath"

	"ir-toolkit/internal/model"
)

func (s *CaseStore) ensureProcesses() error {

	s.processOnce.Do(
		func() {

			s.processByPID =
				make(
					map[uint32]int,
				)

			s.processChildrenByPPID =
				make(
					map[uint32][]int,
				)

			s.processByAuthenticationID =
				make(
					map[string][]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"process",
					"processes.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.processes,
				); err != nil {

				s.processErr =
					err

				return
			}

			for index, process := range s.processes {

				/*
				 * Current process snapshot 中 PID
				 * 应当唯一。
				 */
				s.processByPID[process.PID] =
					index

				if process.PPID != 0 {

					s.processChildrenByPPID[process.PPID] =
						append(
							s.processChildrenByPPID[process.PPID],
							index,
						)
				}

				if process.AuthenticationID != "" {

					key :=
						normalizeLogonID(
							process.AuthenticationID,
						)

					s.processByAuthenticationID[key] =
						append(
							s.processByAuthenticationID[key],
							index,
						)
				}
			}
		},
	)

	return s.processErr
}

func (s *CaseStore) Processes() (
	[]model.Process,
	error,
) {

	if err :=
		s.ensureProcesses(); err != nil {

		return nil,
			err
	}

	return s.processes,
		nil
}

func (s *CaseStore) ProcessByPID(
	pid uint32,
) (
	model.Process,
	bool,
	error,
) {

	if err :=
		s.ensureProcesses(); err != nil {

		return model.Process{},
			false,
			err
	}

	index,
		ok :=
		s.processByPID[pid]

	if !ok {

		return model.Process{},
			false,
			nil
	}

	return s.processes[index],
		true,
		nil
}

func (s *CaseStore) ProcessChildren(
	pid uint32,
) (
	[]model.Process,
	error,
) {

	if err :=
		s.ensureProcesses(); err != nil {

		return nil,
			err
	}

	indexes :=
		s.processChildrenByPPID[pid]

	if len(indexes) == 0 {

		return []model.Process{},
			nil
	}

	children :=
		make(
			[]model.Process,
			0,
			len(indexes),
		)

	for _, index := range indexes {

		children =
			append(
				children,
				s.processes[index],
			)
	}

	return children,
		nil
}

func (s *CaseStore) ProcessesByLogonID(
	logonID string,
) (
	[]model.Process,
	error,
) {

	if logonID == "" {

		return []model.Process{},
			nil
	}

	if err :=
		s.ensureProcesses(); err != nil {

		return nil,
			err
	}

	key :=
		normalizeLogonID(
			logonID,
		)

	indexes :=
		s.processByAuthenticationID[key]

	if len(indexes) == 0 {

		return []model.Process{},
			nil
	}

	processes :=
		make(
			[]model.Process,
			0,
			len(indexes),
		)

	for _, index := range indexes {

		processes =
			append(
				processes,
				s.processes[index],
			)
	}

	return processes,
		nil
}
