package analyzer

import (
	"sort"

	"ir-toolkit/internal/model"
)

func buildHistoricalProcessEdges(
	processes []model.HistoricalProcess,
) []model.HistoricalProcessEdge {

	result :=
		make(
			[]model.HistoricalProcessEdge,
			0,
		)

	byPID :=
		make(
			map[uint32][]model.HistoricalProcess,
		)

	for _, process := range processes {

		byPID[process.PID] =
			append(
				byPID[process.PID],
				process,
			)
	}

	for pid := range byPID {

		sort.Slice(
			byPID[pid],
			func(i, j int) bool {

				return byPID[pid][i].
					Timestamp.
					Before(
						byPID[pid][j].
							Timestamp,
					)
			},
		)
	}

	for _, child := range processes {

		if child.ParentPID == 0 {
			continue
		}

		candidates :=
			byPID[child.ParentPID]

		parent :=
			findHistoricalParent(
				child,
				candidates,
			)

		if parent == nil {
			continue
		}

		result =
			append(
				result,

				model.HistoricalProcessEdge{
					ParentID: parent.ID,

					ChildID: child.ID,

					ParentPID: parent.PID,

					ChildPID: child.PID,

					Type: "parent_child",
				},
			)
	}

	return result
}

func findHistoricalParent(
	child model.HistoricalProcess,
	candidates []model.HistoricalProcess,
) *model.HistoricalProcess {
	if child.ID == "" || child.PID == 0 || child.ParentPID == 0 ||
		child.PID == child.ParentPID || child.Timestamp.IsZero() {
		return nil
	}
	var best *model.HistoricalProcess
	ambiguous := false

	for i := range candidates {
		candidate := &candidates[i]
		if candidate.PID != child.ParentPID {
			continue
		}
		// An undated same-PID record cannot be ordered against the child.
		if candidate.Timestamp.IsZero() {
			return nil
		}
		if candidate.Timestamp.After(child.Timestamp) {
			continue
		}
		if best == nil || candidate.Timestamp.After(best.Timestamp) {
			best, ambiguous = candidate, false
		} else if candidate.Timestamp.Equal(best.Timestamp) {
			ambiguous = true
		}
	}
	// Do not fall back to an older path match when the latest PID instance
	// conflicts. No lifecycle evidence exists for an exited historical parent;
	// only a parent already matched to the current snapshot can be confirmed.
	if best == nil || ambiguous || best.ID == "" || best.ID == child.ID ||
		!best.Timestamp.Before(child.Timestamp) || !best.CurrentProcess {
		return nil
	}
	path := normalizeArtifactPath(best.ProcessPath)
	if path == "" || path != normalizeArtifactPath(child.ParentProcessName) ||
		path != normalizeArtifactPath(best.CurrentProcessPath) {
		return nil
	}
	return best
}
