package local

import (
	"path/filepath"

	"ir-toolkit/internal/model"
)

func (s *CaseStore) ensureLogin() error {

	s.loginOnce.Do(
		func() {

			s.loginByLogonID =
				make(
					map[string]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"login_analysis.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.loginAnalysis,
				); err != nil {

				s.loginErr =
					err

				return
			}

			for index, session := range s.loginAnalysis.Sessions {

				if session.LogonID == "" {
					continue
				}

				key :=
					normalizeLogonID(
						session.LogonID,
					)

				s.loginByLogonID[key] =
					index
			}
		},
	)

	return s.loginErr
}

func (s *CaseStore) LoginAnalysis() (
	*model.LoginAnalysis,
	error,
) {

	if err :=
		s.ensureLogin(); err != nil {

		return nil,
			err
	}

	return &s.loginAnalysis,
		nil
}

func (s *CaseStore) LoginSessions() (
	[]model.LoginSessionAnalysis,
	error,
) {

	if err :=
		s.ensureLogin(); err != nil {

		return nil,
			err
	}

	return s.loginAnalysis.Sessions,
		nil
}

func (s *CaseStore) LoginByLogonID(
	logonID string,
) (
	model.LoginSessionAnalysis,
	bool,
	error,
) {

	if err :=
		s.ensureLogin(); err != nil {

		return model.LoginSessionAnalysis{},
			false,
			err
	}

	if logonID == "" {

		return model.LoginSessionAnalysis{},
			false,
			nil
	}

	key :=
		normalizeLogonID(
			logonID,
		)

	index,
		ok :=
		s.loginByLogonID[key]

	if !ok {

		return model.LoginSessionAnalysis{},
			false,
			nil
	}

	return s.loginAnalysis.Sessions[index],
		true,
		nil
}
