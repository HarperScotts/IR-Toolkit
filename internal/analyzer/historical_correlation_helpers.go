package analyzer

import (
	"ir-toolkit/internal/model"
	"strings"
	"time"
)

func correlationLoginNodeID(
	logonID string,
) string {

	return "login:" +
		normalizeLogonID(
			logonID,
		)
}

func correlationProcessNodeID(
	process model.HistoricalProcess,
) string {

	return process.ID
}

func correlationPowerShellNodeID(
	block model.PowerShellScriptBlock,
) string {

	return block.ID
}

func correlationWindowsActivityNodeID(
	activity model.WindowsActivity,
) string {

	return activity.ID
}

func addCorrelationNode(
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	node model.HistoricalChainNode,
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

func addCorrelationEdge(
	result *model.HistoricalCorrelationAnalysis,
	seen map[string]struct{},
	edge model.CorrelationEdge,
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

	if edge.ID == "" {

		edge.ID =
			"corr:" +
				sanitizeFindingID(
					key,
				)
	}

	result.Edges =
		append(
			result.Edges,
			edge,
		)
}

func correlationConfidence(
	score int,
) string {

	switch {

	case score >= 90:
		return "high"

	case score >= 60:
		return "medium"

	default:
		return "low"
	}
}

func correlationSeverity(
	score int,
) string {

	switch {

	case score >= 120:
		return "critical"

	case score >= 80:
		return "high"

	case score >= 40:
		return "medium"

	default:
		return "low"
	}
}

func withinTimeWindow(
	left time.Time,
	right time.Time,
	window time.Duration,
) bool {

	if left.IsZero() ||
		right.IsZero() {

		return false
	}

	delta :=
		right.Sub(left)

	if delta < 0 {
		delta = -delta
	}

	return delta <= window
}

func normalizeCorrelationUser(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}

func formatDomainUser(
	domain string,
	user string,
) string {

	if domain == "" {
		return user
	}

	return domain +
		`\` +
		user
}
