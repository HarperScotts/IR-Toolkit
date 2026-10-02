package local

import (
	"ir-toolkit/internal/model"
	"path/filepath"
)

func (s *CaseStore) ensurePowerShell() error {

	s.powershellOnce.Do(
		func() {

			s.powershellByID =
				make(
					map[string]int,
				)

			s.powershellByHistoricalProcessID =
				make(
					map[string][]int,
				)

			path :=
				filepath.Join(
					s.caseDir,
					"analysis",
					"powershell_analysis.json",
				)

			if err :=
				readJSONFile(
					path,
					&s.powershellAnalysis,
				); err != nil {

				s.powershellErr =
					err

				return
			}

			for index, block := range s.powershellAnalysis.ScriptBlocks {

				if block.ID != "" {

					s.powershellByID[block.ID] =
						index
				}

				if block.RelatedHistoricalProcessID != "" {

					s.powershellByHistoricalProcessID[block.RelatedHistoricalProcessID] =
						append(
							s.powershellByHistoricalProcessID[block.RelatedHistoricalProcessID],
							index,
						)
				}
			}
		},
	)

	return s.powershellErr
}

func (s *CaseStore) PowerShellAnalysis() (
	*model.PowerShellAnalysis,
	error,
) {

	if err :=
		s.ensurePowerShell(); err != nil {

		return nil,
			err
	}

	return &s.powershellAnalysis,
		nil
}

func (s *CaseStore) PowerShellScriptBlocks() (
	[]model.PowerShellScriptBlock,
	error,
) {

	if err :=
		s.ensurePowerShell(); err != nil {

		return nil,
			err
	}

	return s.powershellAnalysis.ScriptBlocks,
		nil
}

func (s *CaseStore) PowerShellScriptBlockByID(
	id string,
) (
	model.PowerShellScriptBlock,
	bool,
	error,
) {

	if err :=
		s.ensurePowerShell(); err != nil {

		return model.PowerShellScriptBlock{},
			false,
			err
	}

	index,
		ok :=
		s.powershellByID[id]

	if !ok {

		return model.PowerShellScriptBlock{},
			false,
			nil
	}

	return s.powershellAnalysis.ScriptBlocks[index],
		true,
		nil
}

func (s *CaseStore) PowerShellByHistoricalProcessID(
	historicalProcessID string,
) (
	[]model.PowerShellScriptBlock,
	error,
) {

	if historicalProcessID == "" {

		return []model.PowerShellScriptBlock{},
			nil
	}

	if err :=
		s.ensurePowerShell(); err != nil {

		return nil,
			err
	}

	indexes :=
		s.powershellByHistoricalProcessID[historicalProcessID]

	if len(indexes) == 0 {

		return []model.PowerShellScriptBlock{},
			nil
	}

	result :=
		make(
			[]model.PowerShellScriptBlock,
			0,
			len(indexes),
		)

	for _, index := range indexes {

		result =
			append(
				result,
				s.powershellAnalysis.ScriptBlocks[index],
			)
	}

	return result,
		nil
}
