//go:build linux || freebsd || openbsd || netbsd || dragonfly

package biometrics

import "github.com/amenzhinsky/go-polkit"

func CheckBiometrics() bool {
	authority, err := polkit.NewAuthority()
	if err != nil {
		return false
	}

	result, err := authority.CheckAuthorization(
		"com.quexten.bw-bio-handler.unlock",
		nil,
		polkit.CheckAuthorizationAllowUserInteraction, "",
	)

	if err != nil {
		return false
	}

	return result.IsAuthorized
}
