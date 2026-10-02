package ioc

import "ir-toolkit/internal/model"

type CaseEvidence struct {
	Files model.FileTriageSnapshot

	Processes []model.Process

	Network model.NetworkSnapshot

	Persistence model.PersistenceSnapshot

	Timeline model.Timeline
}
