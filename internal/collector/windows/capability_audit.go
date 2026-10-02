//go:build windows

package windows

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"ir-toolkit/internal/model"
)

func checkAuditSubcategory(
	guid string,
) model.CapabilityStatus {

	ctx, cancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)

	defer cancel()

	cmd :=
		exec.CommandContext(
			ctx,
			"auditpol.exe",
			"/get",
			"/subcategory:"+guid,
		)

	output, err :=
		cmd.CombinedOutput()

	text :=
		string(output)

	if err != nil {

		return model.CapabilityStatus{
			Available: false,

			Enabled: false,

			Status: "unknown",

			Reason: strings.TrimSpace(
				text,
			),
		}
	}

	enabled :=
		auditPolicyOutputEnabled(
			text,
		)

	status :=
		"disabled"

	if enabled {
		status =
			"enabled"
	}

	return model.CapabilityStatus{
		Available: true,

		Enabled: enabled,

		Status: status,
	}
}

func auditPolicyOutputEnabled(
	value string,
) bool {

	text :=
		strings.ToLower(
			value,
		)

	patterns :=
		[]string{
			"success",
			"success and failure",
			"成功",
			"成功和失败",
			"成功及失败",
		}

	for _, pattern := range patterns {

		if strings.Contains(
			text,
			strings.ToLower(
				pattern,
			),
		) {

			return true
		}
	}

	return false
}

func checkProcessCreationEventCapability(
	ctx context.Context,
	securityLog model.CapabilityStatus,
	audit model.CapabilityStatus,
) model.CapabilityStatus {

	if !securityLog.Available {

		return model.CapabilityStatus{
			Status: "unavailable",

			Reason: "Security event log is unavailable",
		}
	}

	if !audit.Enabled {

		return model.CapabilityStatus{
			Available: true,

			Enabled: false,

			Status: "disabled",

			Reason: "Audit Process Creation is disabled",
		}
	}

	query :=
		"*[System[(EventID=4688)]]"

	xmlEvents,
		_ :=
		queryEventXML(
			ctx,
			"Security",
			query,
			1,
		)

	if len(xmlEvents) == 0 {

		return model.CapabilityStatus{
			Available: true,

			Enabled: true,

			Status: "enabled_no_events",

			Reason: "process creation auditing is enabled but no 4688 records are currently available",
		}
	}

	return model.CapabilityStatus{
		Available: true,

		Enabled: true,

		Status: "available",
	}
}
