package main

import (
	"github.com/quexten/bw-bio-handler/logging"
	"github.com/quexten/bw-bio-handler/secret"
)

const appID = "com.quexten.bw-bio-handler"

var transportKey []byte
var secretStore secret.SecretStore

func main() {
	s, err := secret.GetStore()
	if err != nil {
		logging.Panicf(err.Error())
	}
	secretStore = s

	transportKey = generateTransportKey()

	setupCommunication()
	readLoop()
}
