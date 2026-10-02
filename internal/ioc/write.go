package ioc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ir-toolkit/internal/model"
)

func WriteScanResult(
	path string,
	result model.IOCScanResult,
) error {

	if err :=
		os.MkdirAll(
			filepath.Dir(path),
			0755,
		); err != nil {

		return fmt.Errorf(
			"create IOC output directory: %w",
			err,
		)
	}

	data, err :=
		json.MarshalIndent(
			result,
			"",
			"  ",
		)

	if err != nil {

		return fmt.Errorf(
			"marshal IOC scan result: %w",
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
