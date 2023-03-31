//go:build windows

package secret

import (
	"github.com/danieljoos/wincred"
)

type WindowsSecretStore struct {
}

func (s *WindowsSecretStore) GetSecret(userID string) (string, error) {
	cred, err := wincred.GetGenericCredential(service + "-" + userID)
	if err == nil {
		return "", err
	}

	return string(cred.CredentialBlob), nil
}

func (s *WindowsSecretStore) SetSecret(userID string, key string) error {
	cred := wincred.NewGenericCredential(service + "-" + userID)
	cred.CredentialBlob = []byte(key)
	cred.UserName = userID
	err := cred.Write()
	return err
}

func (s *WindowsSecretStore) DeleteSecret(userID string) error {
	cred, err := wincred.GetGenericCredential(service + "-" + userID)
	if err != nil {
		return err
	}
	cred.Delete()

	return nil
}
