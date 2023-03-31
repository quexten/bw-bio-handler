//go:build linux || freebsd || openbsd || netbsd || dragonfly

package secret

import (
	"github.com/keybase/dbus"
	"github.com/keybase/go-keychain/secretservice"
)

const colletion = dbus.ObjectPath(secretservice.DefaultCollection)

func GetStore() (SecretStore, error) {
	service, err := secretservice.NewService()
	if err != nil {
		return nil, err
	}
	colletions := []dbus.ObjectPath{dbus.ObjectPath(secretservice.DefaultCollection)}
	service.Unlock(colletions)
	session, err := service.OpenSession(secretservice.AuthenticationDHAES)
	if err != nil {
		return nil, err
	}

	return &SecretServiceSecretStore{
		service: service,
		session: session,
	}, nil
}

type SecretServiceSecretStore struct {
	service *secretservice.SecretService
	session *secretservice.Session
}

func (s *SecretServiceSecretStore) GetSecret(key string) (string, error) {
	item, _ := s.service.SearchCollection(colletion, map[string]string{"account": key})
	if len(item) > 0 {
		secret, err := s.service.GetSecret(item[0], *s.session)
		if err != nil {
			return "", err
		}
		return string(secret), nil
	}
	return "", nil
}

func (s *SecretServiceSecretStore) SetSecret(userId string, key string) error {
	secret, err := s.session.NewSecret([]byte(key))
	if err != nil {
		return err
	}
	_, err = s.service.CreateItem(colletion, secretservice.NewSecretProperties(service, map[string]string{"account": userId}), secret, secretservice.ReplaceBehaviorReplace)
	if err != nil {
		return err
	}
	return nil
}

func (s *SecretServiceSecretStore) DeleteSecret(userId string) error {
	items, err := s.service.SearchCollection(colletion, map[string]string{"account": userId})
	if err != nil {
		return err
	}

	for _, item := range items {
		err := s.service.DeleteItem(item)
		if err != nil {
			return err
		}
	}

	return nil
}
