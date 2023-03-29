package secret

const service = "com.quexten.bitwarden-biometrics-handler"

type SecretStore interface {
	GetSecret(userID string) (string, error)
	SetSecret(userID string, value string) error
	DeleteSecret(userID string) error
}
