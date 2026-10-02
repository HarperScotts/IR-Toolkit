package local

import (
	"errors"
	"ir-toolkit/internal/model"
	"os"
	"path/filepath"
)

func (s *CaseStore) CaseName() string {

	return filepath.Base(
		s.caseDir,
	)
}

func (s *CaseStore) ensureHost() error {

	s.hostOnce.Do(
		func() {

			path :=
				filepath.Join(
					s.caseDir,
					"host",
					"host.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.host,
				); err != nil {

				s.hostErr =
					err
			}
		},
	)

	return s.hostErr
}

func (s *CaseStore) Host() (
	model.HostInfo,
	error,
) {

	if err :=
		s.ensureHost(); err != nil {

		return model.HostInfo{},
			err
	}

	return s.host,
		nil
}

func (s *CaseStore) ensureCapabilities() error {

	s.capabilitiesOnce.Do(
		func() {

			path :=
				filepath.Join(
					s.caseDir,
					"capabilities",
					"capabilities.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.capabilities,
				); err != nil {

				s.capabilitiesErr =
					err
			}
		},
	)

	return s.capabilitiesErr
}

func (s *CaseStore) Capabilities() (
	model.AuditCapabilitySnapshot,
	error,
) {

	if err :=
		s.ensureCapabilities(); err != nil {

		return model.AuditCapabilitySnapshot{},
			err
	}

	return s.capabilities,
		nil
}

func (s *CaseStore) ensureSecurityProviders() error {

	s.securityProvidersOnce.Do(
		func() {

			path :=
				filepath.Join(
					s.caseDir,
					"capabilities",
					"security_providers.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.securityProviders,
				); err != nil {

				if errors.Is(
					err,
					os.ErrNotExist,
				) {

					s.securityProvidersFound =
						false

					return
				}

				s.securityProvidersErr =
					err

				return
			}

			s.securityProvidersFound =
				true
		},
	)

	return s.securityProvidersErr
}

func (s *CaseStore) SecurityProviders() (
	model.SecurityProviderSnapshot,
	bool,
	error,
) {

	if err :=
		s.ensureSecurityProviders(); err != nil {

		return model.SecurityProviderSnapshot{},
			false,
			err
	}

	return s.securityProviders,
		s.securityProvidersFound,
		nil
}

func (s *CaseStore) ensureReport() error {

	s.reportOnce.Do(
		func() {

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"report.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.report,
				); err != nil {

				if errors.Is(
					err,
					os.ErrNotExist,
				) {

					s.reportFound =
						false

					return
				}

				s.reportErr =
					err

				return
			}

			s.reportFound =
				true
		},
	)

	return s.reportErr
}

func (s *CaseStore) Report() (
	model.CaseReport,
	bool,
	error,
) {

	if err :=
		s.ensureReport(); err != nil {

		return model.CaseReport{},
			false,
			err
	}

	return s.report,
		s.reportFound,
		nil
}
