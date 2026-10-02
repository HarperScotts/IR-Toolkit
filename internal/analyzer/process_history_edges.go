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

	var best *model.HistoricalProcess

	for i := range candidates {

		candidate :=
			&candidates[i]

		if candidate.Timestamp.
			After(
				child.Timestamp,
			) {

			break
		}

		/*
			同一个 ProcessCreate 不能作为自己的父节点。
		*/

		if candidate.ID ==
			child.ID {

			continue
		}

		best =
			candidate
	}

	return best
}
