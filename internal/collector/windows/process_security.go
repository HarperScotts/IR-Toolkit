//go:build windows

package windows

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type tokenLUID struct {
	LowPart  uint32
	HighPart int32
}

type tokenStatistics struct {
	TokenID tokenLUID

	AuthenticationID tokenLUID

	ExpirationTime int64

	TokenType uint32

	ImpersonationLevel uint32

	DynamicCharged uint32

	DynamicAvailable uint32

	GroupCount uint32

	PrivilegeCount uint32

	ModifiedID tokenLUID
}

func getProcessSecurityInfo(
	process windows.Handle,
) (
	string,
	string,
	uint32,
	string,
) {

	var token windows.Token

	if err := windows.OpenProcessToken(
		process,
		windows.TOKEN_QUERY,
		&token,
	); err != nil {

		return "", "", 0, ""
	}

	defer token.Close()

	user :=
		getTokenUser(
			token,
		)

	integrity,
		rid :=
		getTokenIntegrityLevel(
			token,
		)

	authenticationID :=
		getTokenAuthenticationID(
			token,
		)

	return user,
		integrity,
		rid,
		authenticationID
}

func getTokenUser(
	token windows.Token,
) string {

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	if tokenUser.User.Sid == nil {
		return ""
	}

	account, domain, _, err :=
		tokenUser.User.Sid.LookupAccount("")

	if err != nil {
		return ""
	}

	if domain == "" {
		return account
	}

	return domain + `\` + account
}

func getTokenIntegrityLevel(
	token windows.Token,
) (string, uint32) {

	// TOKEN_MANDATORY_LABEL contains a SID pointer
	// followed by the SID data.
	buffer := make(
		[]byte,
		256,
	)

	var returned uint32

	if err := windows.GetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		&buffer[0],
		uint32(len(buffer)),
		&returned,
	); err != nil {
		return "", 0
	}

	label := (*windows.Tokenmandatorylabel)(
		unsafe.Pointer(&buffer[0]),
	)

	sid := label.Label.Sid

	if sid == nil {
		return "", 0
	}

	count := sid.SubAuthorityCount()

	if count == 0 {
		return "", 0
	}

	rid := sid.SubAuthority(
		uint32(count - 1),
	)

	return integrityLevelName(rid), rid
}

func integrityLevelName(
	rid uint32,
) string {

	switch rid {

	case 0x1000:
		return "Untrusted"

	case 0x2000:
		return "Low"

	case 0x3000:
		return "Medium"

	case 0x4000:
		return "MediumPlus"

	case 0x5000:
		return "High"

	case 0x6000:
		return "System"

	case 0x7000:
		return "Protected"

	default:
		return "Unknown"
	}
}

func getTokenAuthenticationID(
	token windows.Token,
) string {

	var statistics tokenStatistics

	var returned uint32

	err := windows.GetTokenInformation(
		token,
		windows.TokenStatistics,
		(*byte)(
			unsafe.Pointer(
				&statistics,
			),
		),
		uint32(
			unsafe.Sizeof(
				statistics,
			),
		),
		&returned,
	)

	if err != nil {
		return ""
	}

	return formatLUID(
		statistics.AuthenticationID,
	)
}

func formatLUID(
	value tokenLUID,
) string {

	raw :=
		uint64(
			uint32(
				value.HighPart,
			),
		)<<32 |
			uint64(
				value.LowPart,
			)

	return fmt.Sprintf(
		"0x%x",
		raw,
	)
}
