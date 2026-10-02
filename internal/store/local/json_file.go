package local

import (
	"encoding/json"
	"fmt"
	"os"
)

func readJSONFile(
	path string,
	target any,
) error {

	data,
		err :=
		os.ReadFile(
			path,
		)

	if err != nil {

		return fmt.Errorf(
			"read %q: %w",
			path,
			err,
		)
	}

	if err :=
		json.Unmarshal(
			data,
			target,
		); err != nil {

		return fmt.Errorf(
			"parse %q: %w",
			path,
			err,
		)
	}

	return nil
}
