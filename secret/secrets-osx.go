//go:build darwin

package secret

import (
	"errors"

	"github.com/keybase/go-keychain"
)

func GetStore() (SecretStore, error) {
	return &KeychainSecretStore{}, nil
}

type KeychainSecretStore struct {
}

func (s *KeychainSecretStore) GetSecret(key string) (string, error) {
	return "", errors.New("Not implemented on OSX")
}

func (s *KeychainSecretStore) SetSecret(key string, value string) error {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(service)
	item.SetAccount("gabriel")
	item.SetLabel("A label")
	item.SetAccessGroup(service)
	item.SetData([]byte(key))
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	err := keychain.AddItem(item)

	if err == keychain.ErrorDuplicateItem {
		errors.New("Key is already stored")
	}
	return nil
}

func (s *KeychainSecretStore) DeleteSecret(key string) error {
	return errors.New("Not implemented on OSX")
}
