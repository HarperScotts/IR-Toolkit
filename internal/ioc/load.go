package ioc

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"ir-toolkit/internal/model"
)

func LoadIOCFile(
	path string,
) (model.IOCFile, error) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		return model.IOCFile{},
			fmt.Errorf(
				"read IOC file %q: %w",
				path,
				err,
			)
	}

	var result model.IOCFile

	if err :=
		yaml.Unmarshal(
			data,
			&result,
		); err != nil {

		return model.IOCFile{},
			fmt.Errorf(
				"parse IOC file %q: %w",
				path,
				err,
			)
	}

	if result.Version != 1 {

		return model.IOCFile{},
			fmt.Errorf(
				"unsupported IOC schema version: %d",
				result.Version,
			)
	}

	return result, nil
}
