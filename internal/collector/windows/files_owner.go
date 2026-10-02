//go:build windows

package windows

import "golang.org/x/sys/windows"

func getFileOwner(
	path string,
) string {

	securityDescriptor, err :=
		windows.GetNamedSecurityInfo(
			path,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION,
		)

	if err != nil {
		return ""
	}

	if securityDescriptor == nil {
		return ""
	}

	owner,
		_,
		err :=
		securityDescriptor.Owner()

	if err != nil {
		return ""
	}

	if owner == nil {
		return ""
	}

	account,
		domain,
		_,
		err :=
		owner.LookupAccount("")

	if err != nil {
		return owner.String()
	}

	if domain == "" {
		return account
	}

	return domain +
		`\` +
		account
}
