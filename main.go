package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/quexten/bw-bio-handler/logging"
	"github.com/quexten/bw-bio-handler/pkg/bitw"
	"github.com/quexten/bw-bio-handler/secret"
)

const appID = "com.quexten.bw-bio-handler"

var transportKey []byte
var secretStore secret.SecretStore

func main() {
	if os.Args[1] == "install" {
		install()
		return
	}

	s, err := secret.GetStore()
	if err != nil {
		logging.Panicf(err.Error())
	}
	secretStore = s

	transportKey = generateTransportKey()

	setupCommunication()
	readLoop()
}

func install() {
	fmt.Println("Installing...")
	fmt.Println("Copying polkit policy...")
	workdir := os.Getenv("PWD")
	cmd := exec.Command("pkexec", "cp", workdir+"/biometrics/policies/com.quexten.bw-bio-handler.policy", "/usr/share/polkit-1/actions/")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()

	// check file exists
	_, err := os.Stat("/usr/share/polkit-1/actions/com.quexten.bw-bio-handler.policy")
	if err != nil {
		logging.Panicf("Failed to copy polkit policy: %s", err.Error())
	}

	fmt.Println("Detecting browsers...")
	err = detectAndInstallBrowsers(".config")
	if err != nil {
		panic("Failed to detect browsers: " + err.Error())
	}
	err = detectAndInstallBrowsers(".mozilla")
	if err != nil {
		panic("Failed to detect browsers: " + err.Error())
	}

	fmt.Println("Getting secret...")

	// read email from command line
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Enter email: ")
	scanner.Scan()
	email := scanner.Text()

	fmt.Println("Enter password: ")
	scanner.Scan()
	password := scanner.Text()

	fmt.Println("Enter api url (leave empty for default): ")
	scanner.Scan()
	apiURL := scanner.Text()
	if apiURL == "" {
		apiURL = "https://api.bitwarden.com"
	}

	fmt.Println("Enter identity url (leave empty for default): ")
	scanner.Scan()
	idtURL := scanner.Text()
	if idtURL == "" {
		idtURL = "https://identity.bitwarden.com"
	}

	err = bitw.DoLogin(email, password, apiURL, idtURL)
	if err != nil {
		panic("Failed to login: " + err.Error())
	}
	encKey := bitw.GetEncKeyB64()
	userID := bitw.GetUserID()
	fmt.Println("Got secret!")

	fmt.Println("Storing in libsecret...")
	store, err := secret.GetStore()
	if err != nil {
		panic("Failed to get secret store: " + err.Error())
	}
	store.SetSecret(userID, encKey)

	fmt.Println("Done!")
}

func detectAndInstallBrowsers(startPath string) error {
	home := os.Getenv("HOME")
	err := filepath.Walk(home+"/"+startPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		var tempPath string
		if !strings.HasPrefix(path, home) {
			return nil
		} else {
			tempPath = strings.TrimPrefix(path, home)
		}
		if strings.Count(tempPath, "/") > 3 {
			return nil
		}

		if info.IsDir() && info.Name() == "native-messaging-hosts" {
			fmt.Printf("Found mozilla-like browser: %s\n", path)
			manifest := strings.Replace(templateMozilla, "PATH", os.Getenv("PWD")+"/bw-bio-handler", 1)
			err = os.WriteFile(path+"/com.8bit.bitwarden.json", []byte(manifest), 0644)
		} else if info.IsDir() && info.Name() == "NativeMessagingHosts" {
			fmt.Printf("Found chrome-like browser: %s\n", path)
			manifest := strings.Replace(templateMozilla, "PATH", os.Getenv("PWD")+"/bw-bio-handler", 1)
			err = os.WriteFile(path+"/com.8bit.bitwarden.json", []byte(manifest), 0644)
		}

		return err
	})

	return err
}
