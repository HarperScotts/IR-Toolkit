package local

import (
	"ir-toolkit/internal/model"
	"path/filepath"
)

func (s *CaseStore) ensureWindowsEvents() error {

	s.windowsEventOnce.Do(
		func() {

			s.windowsEventByID =
				make(
					map[string]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"windows_event_analysis.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.windowsEventAnalysis,
				); err != nil {

				s.windowsEventErr =
					err

				return
			}

			for index, activity := range s.windowsEventAnalysis.Activities {

				if activity.ID == "" {
					continue
				}

				s.windowsEventByID[activity.ID] =
					index
			}
		},
	)

	return s.windowsEventErr
}

func (s *CaseStore) WindowsEventAnalysis() (
	*model.WindowsEventAnalysis,
	error,
) {

	if err :=
		s.ensureWindowsEvents(); err != nil {

		return nil,
			err
	}

	return &s.windowsEventAnalysis,
		nil
}

func (s *CaseStore) WindowsActivities() (
	[]model.WindowsActivity,
	error,
) {

	if err :=
		s.ensureWindowsEvents(); err != nil {

		return nil,
			err
	}

	return s.windowsEventAnalysis.Activities,
		nil
}

func (s *CaseStore) WindowsActivityByID(
	id string,
) (
	model.WindowsActivity,
	bool,
	error,
) {

	if err :=
		s.ensureWindowsEvents(); err != nil {

		return model.WindowsActivity{},
			false,
			err
	}

	index,
		ok :=
		s.windowsEventByID[id]

	if !ok {

		return model.WindowsActivity{},
			false,
			nil
	}

	return s.windowsEventAnalysis.Activities[index],
		true,
		nil
}
