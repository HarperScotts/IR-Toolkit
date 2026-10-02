package local

import (
	"errors"
	"os"
	"path/filepath"

	"ir-toolkit/internal/model"
)

func (s *CaseStore) ensureFiles() error {

	s.fileOnce.Do(
		func() {

			s.fileByPath =
				make(
					map[string]int,
				)

			s.fileFindingByPath =
				make(
					map[string]model.FileFinding,
				)

			s.fileFindingByID =
				make(
					map[string]model.FileFinding,
				)

			// ------------------------------------------
			// Raw Evidence
			// ------------------------------------------

			path :=
				filepath.Join(
					s.caseDir,
					"files",
					"files.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.fileSnapshot,
				); err != nil {

				s.fileErr =
					err

				return
			}

			for index, file := range s.fileSnapshot.Files {

				key :=
					normalizeFileEvidencePath(
						file.Path,
					)

				if key == "" {
					continue
				}

				s.fileByPath[key] =
					index
			}

			// ------------------------------------------
			// Analyzer Findings
			// ------------------------------------------

			analysisPath :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"file_analysis.json",
				)

			err :=
				readJSONFile(
					analysisPath,
					&s.fileAnalysis,
				)

			if err != nil {

				/*
				 * Analysis 允许不存在。
				 *
				 * 没有 Analyzer Finding 不应该阻止
				 * Raw File Evidence 被调查。
				 */
				if errors.Is(
					err,
					os.ErrNotExist,
				) {
					return
				}

				s.fileErr =
					err

				return
			}

			for _, finding := range s.fileAnalysis.Findings {

				if finding.ID != "" {

					s.fileFindingByID[finding.ID] =
						finding
				}

				key :=
					normalizeFileEvidencePath(
						finding.Path,
					)

				if key == "" {
					continue
				}

				s.fileFindingByPath[key] =
					finding
			}
		},
	)

	return s.fileErr
}

func (s *CaseStore) Files() (
	*model.FileTriageSnapshot,
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return nil,
			err
	}

	return &s.fileSnapshot,
		nil
}

func (s *CaseStore) FileByPath(
	path string,
) (
	model.FileTriageItem,
	bool,
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return model.FileTriageItem{},
			false,
			err
	}

	key :=
		normalizeFileEvidencePath(
			path,
		)

	index,
		ok :=
		s.fileByPath[key]

	if !ok {

		return model.FileTriageItem{},
			false,
			nil
	}

	return s.fileSnapshot.Files[index],
		true,
		nil
}

func (s *CaseStore) FileFindingByPath(
	path string,
) (
	model.FileFinding,
	bool,
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return model.FileFinding{},
			false,
			err
	}

	finding,
		ok :=
		s.fileFindingByPath[normalizeFileEvidencePath(
			path,
		)]

	return finding,
		ok,
		nil
}

func (s *CaseStore) FileFindings() (
	map[string]model.FileFinding,
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return nil,
			err
	}

	return s.fileFindingByPath,
		nil
}

func (s *CaseStore) FileFindingByID(
	id string,
) (
	model.FileFinding,
	bool,
	error,
) {

	if err :=
		s.ensureFiles(); err != nil {

		return model.FileFinding{},
			false,
			err
	}

	finding,
		ok :=
		s.fileFindingByID[id]

	return finding,
		ok,
		nil
}
