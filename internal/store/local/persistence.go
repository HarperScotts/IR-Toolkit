package local

import (
	"errors"
	"os"
	"path/filepath"

	"ir-toolkit/internal/model"
	"ir-toolkit/internal/store"
)

func (s *CaseStore) ensurePersistence() error {

	s.persistenceOnce.Do(
		func() {

			s.persistenceFindingByKey =
				make(
					map[string]model.PersistenceFinding,
				)

			s.persistenceByID =
				make(
					map[string]int,
				)

			s.serviceByPersistenceID =
				make(
					map[string]int,
				)

			s.runKeyByPersistenceID =
				make(
					map[string]int,
				)

			s.scheduledTaskByPersistenceID =
				make(
					map[string]int,
				)

			s.persistenceFindingByID =
				make(
					map[string]model.PersistenceFinding,
				)

			// ------------------------------------------
			// Raw Evidence
			// ------------------------------------------

			path :=
				filepath.Join(
					s.caseDir,
					"persistence",
					"persistence.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.persistenceSnapshot,
				); err != nil {

				s.persistenceErr =
					err

				return
			}

			// ------------------------------------------
			// Analyzer Findings
			// ------------------------------------------

			analysisPath :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"persistence_analysis.json",
				)

			err :=
				readJSONFile(
					analysisPath,
					&s.persistenceAnalysis,
				)

			if err != nil {

				if !errors.Is(
					err,
					os.ErrNotExist,
				) {

					s.persistenceErr =
						err

					return
				}

			} else {

				for _, finding := range s.persistenceAnalysis.Findings {

					if finding.ID != "" {

						s.persistenceFindingByID[finding.ID] =
							finding
					}

					key :=
						persistenceFindingKey(
							finding.Type,
							finding.Name,
						)

					s.persistenceFindingByKey[key] =
						finding
				}
			}

			s.buildPersistenceItems()
		},
	)

	return s.persistenceErr
}

func (s *CaseStore) buildPersistenceItems() {

	snapshot :=
		&s.persistenceSnapshot

	items :=
		make(
			[]PersistenceItem,
			0,
			len(snapshot.Services)+
				len(snapshot.RunKeys)+
				len(snapshot.ScheduledTasks),
		)

	// --------------------------------------------------
	// Services
	// --------------------------------------------------

	for index, service := range snapshot.Services {

		item :=
			servicePersistenceItem(
				service,
				s.persistenceFindingByKey,
			)

		items =
			append(
				items,
				item,
			)

		s.serviceByPersistenceID[item.ID] =
			index
	}

	// --------------------------------------------------
	// Run Keys
	// --------------------------------------------------

	for index, entry := range snapshot.RunKeys {

		item :=
			runKeyPersistenceItem(
				entry,
				s.persistenceFindingByKey,
			)

		items =
			append(
				items,
				item,
			)

		s.runKeyByPersistenceID[item.ID] =
			index
	}

	// --------------------------------------------------
	// Scheduled Tasks
	// --------------------------------------------------

	for index, task := range snapshot.ScheduledTasks {

		item :=
			scheduledTaskPersistenceItem(
				task,
				s.persistenceFindingByKey,
			)

		items =
			append(
				items,
				item,
			)

		s.scheduledTaskByPersistenceID[item.ID] =
			index
	}

	s.persistenceItems =
		items

	for index, item := range items {

		if item.ID == "" {
			continue
		}

		s.persistenceByID[item.ID] =
			index
	}
}

func (s *CaseStore) PersistenceSnapshot() (
	*model.PersistenceSnapshot,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return nil,
			err
	}

	return &s.persistenceSnapshot,
		nil
}

func (s *CaseStore) PersistenceItems() (
	[]store.PersistenceQueryItem,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return nil,
			err
	}

	items :=
		make(
			[]store.PersistenceQueryItem,
			0,
			len(s.persistenceItems),
		)

	for _, item := range s.persistenceItems {

		items =
			append(
				items,
				s.persistenceQueryItemFromLocal(
					item,
				),
			)
	}

	return items,
		nil
}

func (s *CaseStore) PersistenceItemByID(
	id string,
) (
	store.PersistenceQueryItem,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return store.PersistenceQueryItem{},
			false,
			err
	}

	index,
		ok :=
		s.persistenceByID[id]

	if !ok {

		return store.PersistenceQueryItem{},
			false,
			nil
	}

	return s.persistenceQueryItemFromLocal(
			s.persistenceItems[index],
		),
		true,
		nil
}

func (s *CaseStore) PersistenceFindings() (
	map[string]model.PersistenceFinding,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return nil,
			err
	}

	return s.persistenceFindingByKey,
		nil
}

func (s *CaseStore) PersistenceFindingByID(
	id string,
) (
	model.PersistenceFinding,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return model.PersistenceFinding{},
			false,
			err
	}

	finding,
		ok :=
		s.persistenceFindingByID[id]

	return finding,
		ok,
		nil
}

func (s *CaseStore) ServiceByPersistenceID(
	id string,
) (
	model.ServiceInfo,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return model.ServiceInfo{},
			false,
			err
	}

	index,
		ok :=
		s.serviceByPersistenceID[id]

	if !ok {

		return model.ServiceInfo{},
			false,
			nil
	}

	return s.persistenceSnapshot.Services[index],
		true,
		nil
}

func (s *CaseStore) RunKeyByPersistenceID(
	id string,
) (
	model.RegistryRunEntry,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return model.RegistryRunEntry{},
			false,
			err
	}

	index,
		ok :=
		s.runKeyByPersistenceID[id]

	if !ok {

		return model.RegistryRunEntry{},
			false,
			nil
	}

	return s.persistenceSnapshot.RunKeys[index],
		true,
		nil
}

func (s *CaseStore) ScheduledTaskByPersistenceID(
	id string,
) (
	model.ScheduledTask,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return model.ScheduledTask{},
			false,
			err
	}

	index,
		ok :=
		s.scheduledTaskByPersistenceID[id]

	if !ok {

		return model.ScheduledTask{},
			false,
			nil
	}

	return s.persistenceSnapshot.ScheduledTasks[index],
		true,
		nil
}

func (s *CaseStore) PersistenceFinding(
	evidenceType string,
	name string,
) (
	model.PersistenceFinding,
	bool,
	error,
) {

	if err :=
		s.ensurePersistence(); err != nil {

		return model.PersistenceFinding{},
			false,
			err
	}

	key :=
		persistenceFindingKey(
			evidenceType,
			name,
		)

	finding,
		ok :=
		s.persistenceFindingByKey[key]

	return finding,
		ok,
		nil
}
