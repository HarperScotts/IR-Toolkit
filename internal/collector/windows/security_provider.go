//go:build windows

package windows

import (
	"context"
	"fmt"
	"strings"

	"ir-toolkit/internal/model"
)

type SecurityProviderCollector struct{}

func (c *SecurityProviderCollector) Name() string {
	return "windows_security_providers"
}

func (c *SecurityProviderCollector) Collect(
	ctx context.Context,
) (any, error) {

	result :=
		model.SecurityProviderSnapshot{
			Providers: make(
				[]model.SecurityProvider,
				0,
			),

			EventChannels: make(
				[]model.SecurityEventChannel,
				0,
			),

			Warnings: make(
				[]string,
				0,
			),
		}

	providers,
		warnings :=
		discoverSecurityCenterProviders(
			ctx,
		)

	result.Providers =
		append(
			result.Providers,
			providers...,
		)

	result.Warnings =
		append(
			result.Warnings,
			warnings...,
		)

	discoverSecurityServices(
		&result,
	)

	discoverSecurityEventChannels(
		&result,
	)

	buildSecurityProviderStatistics(
		&result,
	)

	result.Warnings =
		uniqueWarningStrings(
			result.Warnings,
		)

	if len(result.Warnings) > 0 {

		return result,
			fmt.Errorf(
				"security provider discovery completed with warnings: %s",
				strings.Join(
					result.Warnings,
					"; ",
				),
			)
	}

	return result, nil
}
