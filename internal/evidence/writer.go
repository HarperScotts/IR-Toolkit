package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Writer struct {
	Root string
}

func NewWriter(root string) (*Writer, error) {

	if err := os.MkdirAll(
		root,
		0755,
	); err != nil {
		return nil, err
	}

	return &Writer{
		Root: root,
	}, nil
}

func (w *Writer) WriteJSON(
	relativePath string,
	value any,
) (string, error) {

	path := filepath.Join(
		w.Root,
		filepath.Clean(relativePath),
	)

	if err := os.MkdirAll(
		filepath.Dir(path),
		0755,
	); err != nil {
		return "", err
	}

	data, err := json.MarshalIndent(
		value,
		"",
		"  ",
	)

	if err != nil {
		return "",
			fmt.Errorf(
				"marshal %s: %w",
				relativePath,
				err,
			)
	}

	data = append(data, '\n')

	if err := os.WriteFile(
		path,
		data,
		0644,
	); err != nil {

		return "",
			fmt.Errorf(
				"write %s: %w",
				relativePath,
				err,
			)
	}

	return path, nil
}