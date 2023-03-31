// since bitw is an application, not an importable package, this file
// exports the required methods

package bitw

import (
	"context"
	"encoding/base64"
)

func DoLogin(email string, password string, urlApi string, urlIdentity string) error {
	secrets._password = []byte(password)
	secrets._configEmail = email
	apiURL = urlApi
	idtURL = urlIdentity
	defer func() {
		secrets._password = nil
		secrets._configEmail = ""
		apiURL = "https://api.bitwarden.com"
		idtURL = "https://identity.bitwarden.com"
	}()

	ctx := context.Background()
	err := login(ctx, false)
	if err != nil {
		return err
	}

	ensureToken(ctx)
	ctx = context.WithValue(ctx, authToken{}, globalData.AccessToken)

	runSync(ctx)
	secrets.initKeys()

	return nil
}

func GetEncKeyB64() string {
	// encode base64
	return base64.StdEncoding.EncodeToString(secrets.masterKey)
}

func GetUserID() string {
	return globalData.Sync.Profile.ID.String()
}
