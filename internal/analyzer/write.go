package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ir-toolkit/internal/model"
)

func WriteNetworkAnalysis(
	path string,
	analysis model.NetworkAnalysis,
) error {

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {

		return fmt.Errorf(
			"create analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {
		return fmt.Errorf(
			"marshal network analysis: %w",
			err,
		)
	}

	data = append(
		data,
		'\n',
	)

	if err := os.WriteFile(
		path,
		data,
		0644,
	); err != nil {

		return fmt.Errorf(
			"write network analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteProcessRelationshipAnalysis(
	path string,
	analysis model.ProcessRelationshipAnalysis,
) error {

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {

		return fmt.Errorf(
			"create relationship analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal relationship analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write relationship analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WritePersistenceAnalysis(
	path string,
	analysis model.PersistenceAnalysis,
) error {

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {

		return fmt.Errorf(
			"create persistence analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal persistence analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write persistence analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteLoginAnalysis(
	path string,
	analysis model.LoginAnalysis,
) error {

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {

		return fmt.Errorf(
			"create login analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal login analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write login analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteActivityAnalysis(
	path string,
	analysis model.ActivityAnalysis,
) error {

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {

		return fmt.Errorf(
			"create activity analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal activity analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write activity analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteTimeline(
	path string,
	timeline model.Timeline,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create timeline directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			timeline,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal timeline: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write timeline %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteTimelineJSONL(
	path string,
	timeline model.Timeline,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return err
	}

	file, err :=
		os.Create(
			path,
		)

	if err != nil {
		return err
	}

	defer file.Close()

	encoder :=
		json.NewEncoder(
			file,
		)

	for _, event := range timeline.Events {

		if err :=
			encoder.Encode(
				event,
			); err != nil {

			return fmt.Errorf(
				"write timeline event: %w",
				err,
			)
		}
	}

	return nil
}

func WriteFileAnalysis(
	path string,
	analysis model.FileAnalysis,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create file analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal file analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	if err :=
		os.WriteFile(
			path,
			data,
			0644,
		); err != nil {

		return fmt.Errorf(
			"write file analysis %q: %w",
			path,
			err,
		)
	}

	return nil
}

func WriteProcessHistoryAnalysis(
	path string,
	analysis model.ProcessHistoryAnalysis,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create process history analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal process history analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func WritePowerShellAnalysis(
	path string,
	analysis model.PowerShellAnalysis,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create PowerShell analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal PowerShell analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func WriteWindowsEventAnalysis(
	path string,
	analysis model.WindowsEventAnalysis,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create Windows event analysis directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal Windows event analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func WriteHistoricalCorrelationAnalysis(
	path string,
	analysis model.HistoricalCorrelationAnalysis,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create historical correlation directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			analysis,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal historical correlation analysis: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	return os.WriteFile(
		path,
		data,
		0644,
	)
}

func WriteCaseReportJSON(
	path string,
	report model.CaseReport,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create report directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			report,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal case report: %w",
			err,
		)
	}

	data =
		append(
			data,
			'\n',
		)

	return os.WriteFile(
		path,
		data,
		0644,
	)
}
