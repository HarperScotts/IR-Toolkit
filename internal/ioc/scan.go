package ioc

import (
	"context"

	"ir-toolkit/internal/model"
)

func Scan(
	ctx context.Context,
	rules model.IOCFile,
	evidence CaseEvidence,
) model.IOCScanResult {

	result :=
		model.IOCScanResult{
			Matches: make(
				[]model.IOCMatch,
				0,
			),
		}

	result.Statistics.IOCCount =
		countIOCs(
			rules.IOCs,
		)

	scanHashIOCs(
		ctx,
		&result,
		rules.IOCs.Hashes,
		evidence.Files,
	)

	scanPathIOCs(
		ctx,
		&result,
		rules.IOCs.Paths,
		evidence,
	)

	scanProcessNameIOCs(
		ctx,
		&result,
		rules.IOCs.ProcessNames,
		evidence.Processes,
	)

	scanCommandLineIOCs(
		ctx,
		&result,
		rules.IOCs.CommandLines,
		evidence.Processes,
	)

	scanIPIOCs(
		ctx,
		&result,
		rules.IOCs.IPs,
		evidence.Network,
	)

	scanDomainIOCs(
		ctx,
		&result,
		rules.IOCs.Domains,
		evidence,
	)

	result.Statistics.MatchCount =
		uint32(
			len(result.Matches),
		)

	return result
}

func countIOCs(
	set model.IOCSet,
) uint32 {

	return uint32(
		len(set.Hashes) +
			len(set.IPs) +
			len(set.Domains) +
			len(set.Paths) +
			len(set.ProcessNames) +
			len(set.CommandLines),
	)
}
