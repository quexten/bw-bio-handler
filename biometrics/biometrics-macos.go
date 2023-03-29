//go:build darwin

package biometrics

import (
	touchid "github.com/lox/go-touchid"
)

func CheckBiometrics() bool {
	ok, err := touchid.Authenticate("Unlock Bitwarden browser extension")
	return err != nil && ok
}
