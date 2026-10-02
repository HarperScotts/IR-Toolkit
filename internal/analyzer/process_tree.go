package analyzer

import "ir-toolkit/internal/model"

func BuildProcessTree(
	processes []model.Process,
) model.ProcessTree {

	nodes := make(
		map[uint32]*model.ProcessNode,
		len(processes),
	)

	for _, process := range processes {

		p := process

		nodes[p.PID] = &model.ProcessNode{
			Process: p,
		}
	}

	tree := model.ProcessTree{
		Roots: make(
			[]*model.ProcessNode,
			0,
		),
	}

	for _, node := range nodes {

		parent, exists :=
			nodes[node.PPID]

		if !exists ||
			node.PPID == node.PID {

			tree.Roots =
				append(
					tree.Roots,
					node,
				)

			continue
		}

		parent.Children =
			append(
				parent.Children,
				node,
			)
	}

	return tree
}
