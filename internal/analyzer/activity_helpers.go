package analyzer

import (
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

func addActivityNode(
	result *model.ActivityAnalysis,
	seen map[string]struct{},
	node model.ActivityNode,
) {

	if node.ID == "" {
		return
	}

	if _, exists :=
		seen[node.ID]; exists {

		return
	}

	seen[node.ID] =
		struct{}{}

	result.Nodes =
		append(
			result.Nodes,
			node,
		)
}

func addActivityEdge(
	result *model.ActivityAnalysis,
	seen map[string]struct{},
	edge model.ActivityEdge,
) {

	if edge.From == "" ||
		edge.To == "" {

		return
	}

	key :=
		edge.From +
			"|" +
			edge.Type +
			"|" +
			edge.To

	if _, exists :=
		seen[key]; exists {

		return
	}

	seen[key] =
		struct{}{}

	result.Edges =
		append(
			result.Edges,
			edge,
		)
}

func networkNodeID(
	pid uint32,
	connection model.NetworkConnection,
) string {

	raw :=
		fmt.Sprintf(
			"%d-%s-%s-%d",
			pid,
			connection.Protocol,
			connection.RemoteAddress,
			connection.RemotePort,
		)

	return "network:" +
		sanitizeFindingID(
			raw,
		)
}

func formatLoginLabel(
	session model.LoginSessionAnalysis,
) string {

	user :=
		session.User

	if session.Domain != "" {

		user =
			session.Domain +
				`\` +
				session.User
	}

	if session.SourceIP != "" {

		return fmt.Sprintf(
			"%s <- %s",
			user,
			session.SourceIP,
		)
	}

	return user
}

func activitySeverity(
	score int,
) string {

	switch {

	case score >= 90:
		return "critical"

	case score >= 60:
		return "high"

	case score >= 30:
		return "medium"

	default:
		return "low"
	}
}

func joinChainNames(
	values []string,
) string {

	return strings.Join(
		values,
		" -> ",
	)
}
