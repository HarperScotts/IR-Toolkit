package analyzer

import (
	"context"
	"sort"
	"strings"

	"ir-toolkit/internal/model"
)

func AnalyzeLogin(
	ctx context.Context,
	snapshot model.LoginSnapshot,
	network model.NetworkAnalysis,
) model.LoginAnalysis {

	result := model.LoginAnalysis{
		Sessions: make(
			[]model.LoginSessionAnalysis,
			0,
		),

		FailedLoginGroups: make(
			[]model.FailedLoginGroup,
			0,
		),

		Findings: make(
			[]model.LoginFinding,
			0,
		),
	}

	// --------------------------------------------------
	// First pass:
	// 4624 -> Login Session
	// --------------------------------------------------

	sessionMap := make(
		map[string]*model.LoginSessionAnalysis,
	)

	authenticationProcessMap := make(
		map[string][]model.ProcessNetworkAnalysis,
	)

	for _, process := range network.Processes {

		authID :=
			normalizeLogonID(
				process.AuthenticationID,
			)

		if authID == "" {
			continue
		}

		authenticationProcessMap[authID] =
			append(
				authenticationProcessMap[authID],
				process,
			)
	}

	for _, event := range snapshot.Events {

		select {
		case <-ctx.Done():
			return result
		default:
		}

		if event.EventID != 4624 {
			continue
		}

		session := model.LoginSessionAnalysis{
			LogonID: normalizeLogonID(
				event.TargetLogonID,
			),

			Timestamp: event.Timestamp,

			User: event.User,

			Domain: event.Domain,

			SourceIP: event.SourceIP,

			SourcePort: event.SourcePort,

			Workstation: event.Workstation,

			LogonType: event.LogonType,

			LogonTypeName: event.LogonTypeName,

			AuthenticationPackage: event.AuthenticationPackage,

			Events: []uint32{
				4624,
			},
		}

		index := len(result.Sessions)

		result.Sessions = append(
			result.Sessions,
			session,
		)

		if session.LogonID != "" {
			sessionMap[session.LogonID] =
				&result.Sessions[index]
		}

		switch event.LogonType {

		case 10:
			result.Statistics.
				RemoteInteractiveCount++

		case 3:
			result.Statistics.
				NetworkLogonCount++
		}
	}

	// --------------------------------------------------
	// Second pass:
	// 4672 -> match by Logon ID
	// --------------------------------------------------

	for _, event := range snapshot.Events {

		if event.EventID != 4672 {
			continue
		}

		logonID :=
			normalizeLogonID(
				event.TargetLogonID,
			)

		if logonID == "" {
			continue
		}

		session, exists :=
			sessionMap[logonID]

		if !exists {
			continue
		}

		session.Privileged = true

		session.Privileges =
			event.Privileges

		session.Events =
			append(
				session.Events,
				4672,
			)
	}

	// --------------------------------------------------
	//
	// Process -> 4672 session
	// --------------------------------------------------

	for i := range result.Sessions {

		session :=
			&result.Sessions[i]

		if session.LogonID == "" {
			continue
		}

		processes :=
			authenticationProcessMap[session.LogonID]

		for _, process := range processes {

			ref :=
				model.LoginProcessRef{
					PID: process.PID,

					Name: process.ProcessName,

					Path: process.ProcessPath,

					CommandLine: process.CommandLine,

					User: process.User,

					IntegrityLevel: process.IntegrityLevel,

					StartTime: process.StartTime,

					HasNetwork: len(
						process.
							Connections,
					) > 0,

					ExternalConnections: process.
						ExternalConnections,
				}

			session.Processes =
				append(
					session.Processes,
					ref,
				)

			session.ProcessCount++

			if len(
				process.Connections,
			) > 0 {

				session.
					ProcessesWithNetwork++
			}

			if len(
				process.
					ExternalConnections,
			) > 0 {

				session.
					ProcessesWithExternalNetwork++
			}
		}
	}

	// --------------------------------------------------
	// Failed login grouping
	// --------------------------------------------------

	result.FailedLoginGroups =
		groupFailedLogins(
			snapshot.Events,
		)

	// --------------------------------------------------
	// Findings
	// --------------------------------------------------

	for i := range result.Sessions {

		session :=
			&result.Sessions[i]

		if session.Privileged {
			result.Statistics.
				PrivilegedSessionCount++
		}

		findings :=
			analyzeLoginSession(
				session,
			)

		result.Findings =
			append(
				result.Findings,
				findings...,
			)
	}

	// Explicit credential events
	for _, event := range snapshot.Events {

		if event.EventID != 4648 {
			continue
		}

		result.Statistics.
			ExplicitCredentialCount++

		if finding :=
			analyzeExplicitCredentials(
				event,
			); finding != nil {

			result.Findings =
				append(
					result.Findings,
					*finding,
				)
		}
	}

	// Failed groups
	for _, group := range result.FailedLoginGroups {

		result.Statistics.
			FailedLoginCount +=
			group.Count

		if finding :=
			analyzeFailedLoginGroup(
				group,
			); finding != nil {

			result.Findings =
				append(
					result.Findings,
					*finding,
				)
		}
	}

	result.Statistics.SessionCount =
		uint32(
			len(result.Sessions),
		)

	result.Statistics.
		FailedLoginGroupCount =
		uint32(
			len(
				result.
					FailedLoginGroups,
			),
		)

	result.Statistics.FindingCount =
		uint32(
			len(result.Findings),
		)

	for _, finding := range result.Findings {

		switch finding.Severity {

		case "critical":
			result.Statistics.
				CriticalCount++

		case "high":
			result.Statistics.
				HighCount++

		case "medium":
			result.Statistics.
				MediumCount++

		case "low":
			result.Statistics.
				LowCount++
		}
	}

	sort.Slice(
		result.Sessions,
		func(i, j int) bool {

			return result.Sessions[i].
				Timestamp.
				After(
					result.Sessions[j].
						Timestamp,
				)
		},
	)

	return result
}

func normalizeLogonID(
	value string,
) string {

	return strings.ToLower(
		strings.TrimSpace(
			value,
		),
	)
}
