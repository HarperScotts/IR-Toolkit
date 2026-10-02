package local

import (
	"fmt"
	"ir-toolkit/internal/model"
	"path/filepath"
)

func (s *CaseStore) ensureIOC() error {

	s.iocOnce.Do(
		func() {

			s.iocByID =
				make(
					map[string]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"ioc_matches.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.iocScanResult,
				); err != nil {

				s.iocErr =
					err

				return
			}

			for index := range s.iocScanResult.Matches {

				id :=
					fmt.Sprintf(
						"ioc-match:%d",
						index,
					)

				s.iocByID[id] =
					index
			}
		},
	)

	return s.iocErr
}

func (s *CaseStore) IOCScanResult() (
	*model.IOCScanResult,
	error,
) {

	if err :=
		s.ensureIOC(); err != nil {

		return nil,
			err
	}

	return &s.iocScanResult,
		nil
}

func (s *CaseStore) IOCMatches() (
	[]model.IOCMatch,
	error,
) {

	if err :=
		s.ensureIOC(); err != nil {

		return nil,
			err
	}

	return s.iocScanResult.Matches,
		nil
}

func (s *CaseStore) IOCMatchByID(
	id string,
) (
	model.IOCMatch,
	bool,
	error,
) {

	if err :=
		s.ensureIOC(); err != nil {

		return model.IOCMatch{},
			false,
			err
	}

	index,
		ok :=
		s.iocByID[id]

	if !ok {

		return model.IOCMatch{},
			false,
			nil
	}

	return s.iocScanResult.Matches[index],
		true,
		nil
}
