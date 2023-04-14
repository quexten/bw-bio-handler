## bw-bio-handler

### Disclaimer: This is not an official bitwarden project. Please do not direct any issues related to biometrics unlock while using this tool to the Bitwarden team. Instead create a GitHub issue on this repo.

This tool is a simple implementation of the bitwarden browser IPC protocol. It only implements the subset of commands necessary to make biometrics unlock work. This replaces the need for the desktop application and ipc proxy running in the background, and enables support on unix systems (which is currently not merged in the official bitwarden desktop application). On my system this uses about 4MB of memory, compared to the official desktop application + proxy which uses about 300-400MB.

Currently, only unix support is implemented (linux is tested, BSDs are untested but might work), MacOS and Windows support should not be too much work, but I don't have the resources atm to implement / test it. Pull requests are welcome.

Basically, with the official desktop application, the communication is:
Browser -stdio-> IPC Proxy -> Bitwarden Desktop Application

With this tool, the communication is:
Browser -stdio-> bitw-bio-handler

## Requirements
As of now, only Linux based systems are tested to work.
You need to at least have a working, unlocked keyring (such as gnome-keyring) that supports the DBus Secret Service API (this is installed by default on most distributions).
Any chromium or firefox based browser should work, as long as they are *not* installed as a Snap or Flatpak. Snap / Flatpaks currently prevent the inter-process communication required for the extension to communicate with this tool (or the official Bitwarden desktop client). This will be fixed in the future by the Web Extensions xdg portal. Finally, this tool only prompts system authentication (password) via polkit. If you want biometrics unlock to work, you need to configure biometrics to work with polkit for your distribution.

## Installation & Setup
After cloning the repository to $GOPATH/src/github.com/quexten/bw-bio-handler, run:
### Automatic setup
Run
```bash
go mod download
go mod tidy
go build .
go run . install
```
And follow the steps printed in the console.
Afterwards, just enable your biometrics unlock in the browser extension, and you're good to go.

### Manual setup
(Sorry, this manual setup is a bit involved atm)

First clone this repo to your go src directory.

First, the polkit policy needs to be set up. Copy ./biometrics/policies/com.quexten.bw-bio-handler.xml to
/usr/share/polkit-1/actions/

To test if the policy is set up correctly, run:
```
go test ./biometrics/
```

Next obtain your encryption key. To do this, go to your logged in web vault, and paste:
```js
console.log((await this.bitwardenContainerService.cryptoService.getKey()).encKeyB64)
```
into your browser console. This is your vault's encryption key, do not write it down anywhere, and do not save it in unencrypted form.

Then, get your userid: 
```js
console.log(await this.bitwardenContainerService.cryptoService.stateService.getActiveUserIdFromStorage())
```

Next, run the following in your system's terminal (not the browser), replacing the <userid> with the user id you got in the previous step.
```
secret-tool store --label "com.quexten.bitwarden-biometrics-handler" account <userid>
```
and enter the encryption key when asked for the Password.

Finally, we need to set up the browser manifest, and point it to this tool.
Copy the manifest for your browser from ./manifests to the correct location:
- Firefox: ~/.mozilla/native-messaging-hosts/
- Chrome: ~/.config/google-chrome/NativeMessagingHosts/
- (for other browsers check your browser's documentation)

Then, edit the manifest, and change the path to the location of the compiled binary, f.e:
```
"path": "/home/user/go/src/github.com/quexten/bw-bio-handler/bw-bio-handler"
```

Finally, enable biometrics unlock in the browser extension, and you're good to go.

## Security & Architecture

### Official implementation

Browser extension -stdio-> IPC Proxy -ipc-> Desktop App -> OS Biometrics
                                                        -> OS Secret Store

The official (desktop app) implementation works like this: The browser extension generates a public key and sends it to the desktop app via the proxy. The desktop app generates a random, symmetric transport key, and sends it to the extension, encrypted with the public key. This transport key encrypts all communication between desktop app and browser. There is no cryptographic proof that the browser and desktop app are signed into the same account.

The desktop app stores a biometric key, which is equal to the account's encryption key in the os' native secret store. When asked for, it sends this biometric key to the browser extension, which then tries to use it as its encryption key.

### This tool

Browser extension -stdio-> this tool -> OS Biometrics
                                     -> OS Secret Store

The cryptographic protocol is the same as in the official implementation. The biometric key gets stored in the secret store of the operating system. The biometrics api is not used to get a cryptographic key but simply to determine access control to the secret store.

Beware that the secret store (which also stores things like ssh keys, and the password for the browser's encrypted storage) is user accessible. Other processes running under the same user can access this information, but that is true regardless of whether this tool is used or not.

### Testing
To test, run:

```go
go test ./...
```

The biometrics test is interactive, so make sure you actually unlock during the test or it will fail.
