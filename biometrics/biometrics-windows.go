//go:build windows

package biometrics

func CheckBiometrics() bool {
	panic("Not implemented on Windows")
	return false
}
