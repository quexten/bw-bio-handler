package biometrics_test

import (
	"testing"

	"github.com/quexten/bw-bio-handler/biometrics"
)

func TestUnlock(t *testing.T) {
	authorization := biometrics.CheckBiometrics()
	if !authorization {
		t.Fatalf("Authorization failed")
	}
}
