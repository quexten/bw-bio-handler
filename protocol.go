package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"

	"github.com/quexten/bw-bio-handler/biometrics"
	"github.com/quexten/bw-bio-handler/logging"
)

func readLoop() {
	v := bufio.NewReader(os.Stdin)
	s := bufio.NewReaderSize(v, bufferSize)

	lengthBytes := make([]byte, 4)
	lengthNum := int(0)

	send(SendMessage{
		Command: "connected",
		AppID:   appID,
	})

	for b, err := s.Read(lengthBytes); b > 0 && err == nil; b, err = s.Read(lengthBytes) {
		lengthNum = readMessageLength(lengthBytes)

		content := make([]byte, lengthNum)
		_, err := s.Read(content)
		if err != nil && err != io.EOF {
			logging.Panicf(err.Error())
		}

		parseMessage(content)
	}
}

func parseMessage(msg []byte) {
	logging.Debugf("Received message: " + string(msg))

	var genericMessage GenericRecvMessage
	err := json.Unmarshal(msg, &genericMessage)
	if err != nil {
		logging.Panicf("Unable to unmarshal json to struct: " + err.Error())
	}
	if _, ok := (genericMessage.Message.(map[string]interface{})["command"]); ok {
		logging.Debugf("Message is unencrypted")

		var unmsg UnencryptedRecvMessage
		err := json.Unmarshal(msg, &unmsg)
		if err != nil {
			logging.Panicf("Unable to unmarshal json to struct: " + err.Error())
		}

		handleUnencryptedMessage(unmsg)
	} else {
		logging.Debugf("Message is encrypted")

		var encmsg EncryptedRecvMessage
		err := json.Unmarshal(msg, &encmsg)
		if err != nil {
			logging.Panicf("Unable to unmarshal json to struct: " + err.Error())
		}

		decryptedMessage := decryptStringSymmetric(transportKey, encmsg.Message.IV, encmsg.Message.Data)
		var payloadMsg PayloadMessage
		err = json.Unmarshal([]byte(decryptedMessage), &payloadMsg)
		if err != nil {
			logging.Panicf("Unable to unmarshal json to struct: " + err.Error())
		}

		handlePayloadMessage(payloadMsg, genericMessage.AppID)
	}
}

func handleUnencryptedMessage(msg UnencryptedRecvMessage) {
	logging.Debugf("Received unencrypted message: %+v", msg.Message)
	logging.Debugf("  with command: %s", msg.Message.Command)

	switch msg.Message.Command {
	case "setupEncryption":
		sharedSecret, err := rsaEncrypt(msg.Message.PublicKey, transportKey)
		if err != nil {
			logging.Panicf(err.Error())
		}
		send(SendMessage{
			Command:      "setupEncryption",
			AppID:        msg.AppID,
			SharedSecret: sharedSecret,
		})
		break
	}
}
func handlePayloadMessage(msg PayloadMessage, appID string) {
	logging.Debugf("Received unencrypted message: %+v", msg)

	switch msg.Command {
	case "biometricUnlock":
		logging.Debugf("Biometric unlock requested")
		isAuthorized := biometrics.CheckBiometrics()
		logging.Debugf("Biometrics authorized: %t", isAuthorized)

		if isAuthorized {
			key, err := secretStore.GetSecret(msg.UserId)
			if err != nil {
				logging.Panicf(err.Error())
			}

			var payloadMsg ReceiveMessage = ReceiveMessage{
				Command:   "biometricUnlock",
				Response:  "unlocked",
				Timestamp: msg.Timestamp,
				KeyB64:    key,
			}
			payloadStr, err := json.Marshal(payloadMsg)
			if err != nil {
				logging.Panicf(err.Error())
			}

			encStr := encryptStringSymmetric(transportKey, payloadStr)
			send(SendMessage{
				AppID:   appID,
				Message: encStr,
			})
		} else {
			logging.Panicf("Biometrics not authorized")
		}
		break
	}
}
