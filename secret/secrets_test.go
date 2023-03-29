package secret_test

import (
	"testing"

	"github.com/quexten/bw-bio-handler/secret"
)

func TestStoreFunctionality(t *testing.T) {
	store, err := secret.GetStore()
	if err != nil {
		t.Fatal(err)
	}

	err = store.SetSecret("bw-bio-test", "test")
	if err != nil {
		t.Fatal(err)
	}

	secret, err := store.GetSecret("bw-bio-test")
	if err != nil {
		t.Fatal(err)
	}

	if secret != "test" {
		t.Fatal("Secret not equal to test")
	}

	err = store.DeleteSecret("bw-bio-test")
	if err != nil {
		t.Fatal(err)
	}

	secret, err = store.GetSecret("bw-bio-test")
	if err != nil {
		t.Fatal(err)
	}

	if secret != "" {
		t.Fatal("Secret not empty after deletion")
	}
}
