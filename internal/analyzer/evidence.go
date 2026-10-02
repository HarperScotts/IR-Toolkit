package analyzer

import (
	"encoding/json"
	"fmt"
	"os"

	"ir-toolkit/internal/model"
)

func LoadProcesses(
	path string,
) ([]model.Process, error) {

	data, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf(
			"read process evidence %q: %w",
			path,
			err,
		)
	}

	var processes []model.Process

	if err := json.Unmarshal(
		data,
		&processes,
	); err != nil {

		return nil, fmt.Errorf(
			"parse process evidence %q: %w",
			path,
			err,
		)
	}

	return processes, nil
}

func LoadNetworkConnections(
	path string,
) ([]model.NetworkConnection, error) {

	data, err := os.ReadFile(path)

	if err != nil {
		return nil, fmt.Errorf(
			"read network evidence %q: %w",
			path,
			err,
		)
	}

	var snapshot model.NetworkSnapshot

	if err := json.Unmarshal(
		data,
		&snapshot,
	); err != nil {

		return nil, fmt.Errorf(
			"parse network evidence %q: %w",
			path,
			err,
		)
	}

	return snapshot.Connections, nil
}

func LoadPersistence(
	path string,
) (model.PersistenceSnapshot, error) {

	data, err := os.ReadFile(path)

	if err != nil {

		return model.PersistenceSnapshot{},
			fmt.Errorf(
				"read persistence evidence %q: %w",
				path,
				err,
			)
	}

	var snapshot model.PersistenceSnapshot

	if err := json.Unmarshal(
		data,
		&snapshot,
	); err != nil {

		return model.PersistenceSnapshot{},
			fmt.Errorf(
				"parse persistence evidence %q: %w",
				path,
				err,
			)
	}

	return snapshot, nil
}

func LoadLogin(
	path string,
) (model.LoginSnapshot, error) {

	data, err := os.ReadFile(path)

	if err != nil {
		return model.LoginSnapshot{},
			fmt.Errorf(
				"read login evidence %q: %w",
				path,
				err,
			)
	}

	var snapshot model.LoginSnapshot

	if err := json.Unmarshal(
		data,
		&snapshot,
	); err != nil {

		return model.LoginSnapshot{},
			fmt.Errorf(
				"parse login evidence %q: %w",
				path,
				err,
			)
	}

	return snapshot, nil
}

func LoadHost(
	path string,
) (model.HostInfo, error) {

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {

		return model.HostInfo{},
			fmt.Errorf(
				"read host evidence %q: %w",
				path,
				err,
			)
	}

	var host model.HostInfo

	if err :=
		json.Unmarshal(
			data,
			&host,
		); err != nil {

		return model.HostInfo{},
			fmt.Errorf(
				"parse host evidence %q: %w",
				path,
				err,
			)
	}

	return host, nil
}

func LoadManifest(
	path string,
) (model.Manifest, error) {

	data, err :=
		os.ReadFile(
			path,
		)

	if err != nil {

		return model.Manifest{},
			fmt.Errorf(
				"read manifest %q: %w",
				path,
				err,
			)
	}

	var manifest model.Manifest

	if err :=
		json.Unmarshal(
			data,
			&manifest,
		); err != nil {

		return model.Manifest{},
			fmt.Errorf(
				"parse manifest %q: %w",
				path,
				err,
			)
	}

	return manifest, nil
}

func LoadFiles(
	path string,
) (model.FileTriageSnapshot, error) {

	data, err := os.ReadFile(path)

	if err != nil {
		return model.FileTriageSnapshot{},
			fmt.Errorf(
				"read file evidence %q: %w",
				path,
				err,
			)
	}

	var snapshot model.FileTriageSnapshot

	if err := json.Unmarshal(
		data,
		&snapshot,
	); err != nil {

		return model.FileTriageSnapshot{},
			fmt.Errorf(
				"parse file evidence %q: %w",
				path,
				err,
			)
	}

	return snapshot, nil
}

func LoadProcessEvents(
	path string,
) (model.ProcessEventSnapshot, error) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		return model.ProcessEventSnapshot{},
			fmt.Errorf(
				"read process event evidence %q: %w",
				path,
				err,
			)
	}

	var snapshot model.ProcessEventSnapshot

	if err :=
		json.Unmarshal(
			data,
			&snapshot,
		); err != nil {

		return model.ProcessEventSnapshot{},
			fmt.Errorf(
				"parse process event evidence %q: %w",
				path,
				err,
			)
	}

	return snapshot, nil
}

func LoadPowerShellEvents(
	path string,
) (model.PowerShellEventSnapshot, error) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		return model.PowerShellEventSnapshot{},
			fmt.Errorf(
				"read PowerShell event evidence %q: %w",
				path,
				err,
			)
	}

	var snapshot model.PowerShellEventSnapshot

	if err :=
		json.Unmarshal(
			data,
			&snapshot,
		); err != nil {

		return model.PowerShellEventSnapshot{},
			fmt.Errorf(
				"parse PowerShell event evidence %q: %w",
				path,
				err,
			)
	}

	return snapshot, nil
}

func LoadCapabilities(
	path string,
) (
	model.AuditCapabilitySnapshot,
	error,
) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		return model.AuditCapabilitySnapshot{},
			fmt.Errorf(
				"read capabilities %q: %w",
				path,
				err,
			)
	}

	var result model.AuditCapabilitySnapshot

	if err :=
		json.Unmarshal(
			data,
			&result,
		); err != nil {

		return model.AuditCapabilitySnapshot{},
			fmt.Errorf(
				"parse capabilities %q: %w",
				path,
				err,
			)
	}

	return result, nil
}

func LoadWindowsEvents(
	path string,
) (model.WindowsEventSnapshot, error) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		return model.WindowsEventSnapshot{},
			fmt.Errorf(
				"read Windows event evidence %q: %w",
				path,
				err,
			)
	}

	var result model.WindowsEventSnapshot

	if err :=
		json.Unmarshal(
			data,
			&result,
		); err != nil {

		return model.WindowsEventSnapshot{},
			fmt.Errorf(
				"parse Windows event evidence %q: %w",
				path,
				err,
			)
	}

	return result, nil
}

func TryLoadIOCScanResult(
	path string,
) (*model.IOCScanResult, error) {

	data, err :=
		os.ReadFile(path)

	if err != nil {

		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	var result model.IOCScanResult

	if err :=
		json.Unmarshal(
			data,
			&result,
		); err != nil {

		return nil, err
	}

	return &result, nil
}
