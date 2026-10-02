package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
)

type failedLoginKey struct {
	SourceIP string

	User string
}

func groupFailedLogins(
	events []model.LoginEvent,
) []model.FailedLoginGroup {

	groups :=
		make(
			map[failedLoginKey]*model.FailedLoginGroup,
		)

	for _, event := range events {

		if event.EventID != 4625 {
			continue
		}

		key :=
			failedLoginKey{

				SourceIP: event.SourceIP,

				User: strings.ToLower(
					event.User,
				),
			}

		group, exists :=
			groups[key]

		if !exists {

			group =
				&model.FailedLoginGroup{

					SourceIP: event.SourceIP,

					User: event.User,

					FirstSeen: event.Timestamp,

					LastSeen: event.Timestamp,

					LogonTypes: make(
						[]uint32,
						0,
					),
				}

			groups[key] =
				group
		}

		group.Count++

		if event.Timestamp.
			Before(
				group.FirstSeen,
			) {

			group.FirstSeen =
				event.Timestamp
		}

		if event.Timestamp.
			After(
				group.LastSeen,
			) {

			group.LastSeen =
				event.Timestamp
		}

		if !containsUint32(
			group.LogonTypes,
			event.LogonType,
		) {

			group.LogonTypes =
				append(
					group.LogonTypes,
					event.LogonType,
				)
		}
	}

	result :=
		make(
			[]model.FailedLoginGroup,
			0,
			len(groups),
		)

	for _, group := range groups {

		result =
			append(
				result,
				*group,
			)
	}

	sort.Slice(
		result,
		func(i, j int) bool {

			return result[i].Count >
				result[j].Count
		},
	)

	return result
}

func containsUint32(
	values []uint32,
	target uint32,
) bool {

	for _, value := range values {

		if value == target {
			return true
		}
	}

	return false
}

func analyzeFailedLoginGroup(
	group model.FailedLoginGroup,
) *model.LoginFinding {

	if group.Count < 5 {
		return nil
	}

	score := 20

	reasons :=
		[]string{
			fmt.Sprintf(
				"%d failed logon attempts from the same source/user pair",
				group.Count,
			),
		}

	switch {

	case group.Count >= 50:

		score = 70

		reasons =
			append(
				reasons,
				"high-volume failed authentication activity",
			)

	case group.Count >= 20:

		score = 50

	case group.Count >= 10:

		score = 35
	}

	finding :=
		&model.LoginFinding{

			ID: "LOGIN-FAILED-" +
				sanitizeFindingID(
					group.SourceIP+
						"-"+
						group.User,
				),

			Type: "failed_logons",

			Title: "Repeated failed authentication attempts",

			Timestamp: group.LastSeen,

			User: group.User,

			SourceIP: group.SourceIP,

			Score: score,

			Reasons: reasons,

			RelatedEvents: []uint32{
				4625,
			},
		}

	finding.Severity =
		loginSeverity(
			score,
		)

	return finding
}
