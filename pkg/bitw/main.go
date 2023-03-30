// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package bitw

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kenshaw/ini"

	errgroup "golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

var flagSet = flag.NewFlagSet("bitw", flag.ContinueOnError)

func init() { flagSet.Usage = usage }

func usage() {
	fmt.Fprintf(os.Stderr, `
Usage of bitw:

	bitw [command]

Commands:

	help    show a command's help text
	sync    fetch the latest data from the server
	login   force a new login, even if not necessary
	dump    list all the stored login secrets
	serve   start the org.freedesktop.secrets D-Bus service
	config  print the current configuration
`[1:])
	flagSet.PrintDefaults()
}

func main() { os.Exit(main1(os.Stderr)) }

func main1(stderr io.Writer) int {
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		return 2
	}
	args := flagSet.Args()
	if err := run(args...); err != nil {
		switch err {
		case context.Canceled:
			return 0
		case flag.ErrHelp:
			return 2
		}
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	return 0
}

// These can be overriden by the config.
var (
	apiURL = "https://api.bitwarden.com"
	idtURL = "https://identity.bitwarden.com"
)

// readLine is similar to term.ReadPassword, but it doesn't use key codes.
func readLine(prompt string) ([]byte, error) {
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	defer fmt.Fprintln(os.Stderr)

	var buf [1]byte
	var line []byte
	for {
		n, err := os.Stdin.Read(buf[:])
		if n > 0 {
			switch buf[0] {
			case '\n', '\r':
				return line, nil
			default:
				line = append(line, buf[0])
			}
		} else if err != nil {
			if err == io.EOF && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
	}
}

func passwordPrompt(prompt string) ([]byte, error) {
	// TODO: Support cancellation with ^C. Currently not possible in any
	// simple way. Closing os.Stdin on cancel doesn't seem to do the trick
	// either. Simply doing an os.Exit keeps the terminal broken because of
	// ReadPassword.

	fd := int(os.Stdin.Fd())
	switch {
	case term.IsTerminal(fd):
		fmt.Fprintf(os.Stderr, "%s: ", prompt)
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err == nil && len(password) == 0 {
			err = io.ErrUnexpectedEOF
		}
		return password, err
	case os.Getenv("FORCE_STDIN_PROMPTS") == "true":
		return readLine(prompt)
	default:
		return nil, fmt.Errorf("need a terminal to prompt for a password")
	}
}

var (
	config     *ini.File
	globalData dataFile

	saveData bool

	secrets secretCache
)

func init() { secrets.data = &globalData }

type dataFile struct {
	path string

	DeviceID       string
	AccessToken    string
	RefreshToken   string
	TokenExpiry    time.Time
	KDF            KDFType
	KDFIterations  int
	KDFMemory      int
	KDFParallelism int

	LastSync time.Time
	Sync     SyncData
}

func loadDataFile(path string) error {
	globalData.path = path
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&globalData); err != nil {
		return err
	}
	return nil
}

func (f *dataFile) Save() error {
	bs, err := json.MarshalIndent(f, "", "\t")
	if err != nil {
		return err
	}
	bs = append(bs, '\n')
	if err := os.MkdirAll(filepath.Dir(f.path), 0o755); err != nil {
		return err
	}
	return ioutil.WriteFile(f.path, bs, 0o600)
}

func run(args ...string) (err error) {
	if len(args) == 0 {
		flagSet.Usage()
		return flag.ErrHelp
	}

	switch args[0] {
	case "help":
		// TODO: per-command help
		flagSet.Usage()
		return flag.ErrHelp
	}
	dir := os.Getenv("CONFIG_DIR")
	if dir == "" {
		if dir, err = os.UserConfigDir(); err != nil {
			return err
		}
		dir = filepath.Join(dir, "bitw")
	}
	config, err = ini.LoadFile(filepath.Join(dir, "config"))
	if err != nil {
		return err
	}
	for _, section := range config.AllSections() {
		if section.Name() != "" {
			return fmt.Errorf("sections are not used in config files yet")
		}
		for _, key := range section.Keys() {
			// note that these are lowercased
			switch key {
			case "email":
				secrets._configEmail = section.Get(key)
			case "apiurl":
				apiURL = section.Get(key)
			case "identityurl":
				idtURL = section.Get(key)
			default:
				return fmt.Errorf("unknown config key: %q", key)
			}
		}
	}

	dataPath := filepath.Join(dir, "data.json")
	if err := loadDataFile(dataPath); err != nil {
		return fmt.Errorf("could not load %s: %v", dataPath, err)
	}

	if args[0] == "config" {
		fmt.Printf("email       = %q\n", secrets.email())
		fmt.Printf("apiURL      = %q\n", apiURL)
		fmt.Printf("identityURL = %q\n", idtURL)
		return nil
	}

	defer func() {
		if !saveData {
			return
		}
		if err1 := globalData.Save(); err == nil {
			err = err1
		}
	}()

	if globalData.DeviceID == "" {
		globalData.DeviceID = uuid.New().String()
		saveData = true
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	// If stdin is a terminal, ensure we reset its state before exiting.
	stdinFD := int(os.Stdin.Fd())
	stdinOldState, _ := term.GetState(stdinFD)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-c
		cancel()

		// If we still haven't exited after 200ms,
		// we're probably stuck reading a password.
		// Unfortunately, term.ReadPassword can't be cancelled right now.
		//
		// The least we can do is restore the terminal to its original state,
		// and exit the entire program.
		// TODO: probably revisit this at some point.
		time.Sleep(200 * time.Millisecond)
		if stdinOldState != nil { // if nil, stdin is not a terminal
			_ = term.Restore(stdinFD, stdinOldState)
		}
		fmt.Println()
		os.Exit(0)
	}()

	ctx = context.WithValue(ctx, authToken{}, globalData.AccessToken)
	switch args[0] {
	case "login":
		if err := login(ctx, false); err != nil {
			return err
		}
	case "sync":
		if err := ensureToken(ctx); err != nil {
			return err
		}
		if err := runSync(ctx); err != nil {
			return err
		}
	case "dump":
		// Make sure we have the password before printing anything.
		if _, err := secrets.password(); err != nil {
			return err
		}
		secrets.initKeys()
		format := args[1]
		dumpType := args[2]

		// Split the ciphers into categories, for printing.
		// Don't use text/tabwriter, as deciphering hundreds can be slow.
		var logins []*Cipher
		var identities []*Cipher
		var secureNotes []*Cipher
		var cards []*Cipher

		for i := range globalData.Sync.Ciphers {
			cipher := &globalData.Sync.Ciphers[i]
			if cipher.Login != nil {
				logins = append(logins, cipher)
			} else if cipher.Identity != nil {
				identities = append(identities, cipher)
			} else if cipher.SecureNote != nil {
				if cipher.Notes == nil {
					continue
				}

				secureNotes = append(secureNotes, cipher)
			} else if cipher.Card != nil {
				cards = append(cards, cipher)
			} else {
				return fmt.Errorf("unknown cipher type: %v", cipher)
			}
		}

		if dumpType == "all" || dumpType == "logins" {
			printDump("logins", logins, func(c Cipher) []CipherString {
				return []CipherString{c.Name, c.Login.Username, c.Login.Password}
			}, []string{"name", "username", "password"}, format)
		}
		if dumpType == "all" || dumpType == "identities" {
			printDump("identities", identities, func(c Cipher) []CipherString {
				return []CipherString{c.Identity.Title, c.Identity.FirstName, c.Identity.MiddleName, c.Identity.LastName, c.Identity.Address1, c.Identity.Address2, c.Identity.Address3, c.Identity.City, c.Identity.State, c.Identity.PostalCode, c.Identity.Country, c.Identity.Company, c.Identity.Email, c.Identity.Phone, c.Identity.SSN, c.Identity.Username, c.Identity.PassportNumber, c.Identity.LicenseNumber}
			}, []string{"name", "title", "first name", "middle name", "last name", "address 1", "address 2", "address 3", "city", "state", "postal code", "country", "company", "email", "phone", "ssn", "username", "passport number", "license number"}, format)
		}

		if dumpType == "all" || dumpType == "secure notes" {
			printDump("secure notes", secureNotes, func(c Cipher) []CipherString {
				return []CipherString{c.Name, *c.Notes}
			}, []string{"name", "text"}, format)
		}

		if dumpType == "all" || dumpType == "cards" {
			printDump("cards", cards, func(c Cipher) []CipherString {
				return []CipherString{c.Name, c.Card.CardholderName, c.Card.Brand, c.Card.Number, c.Card.ExpMonth, c.Card.ExpYear, c.Card.Code}
			}, []string{"name", "cardholder name", "brand", "number", "exp month", "exp year", "code"}, format)
		}

		return nil
	case "serve":
		// if err := serveDBus(ctx); err != nil {
		// 	return err
		// }
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %q\n", args[0])
		flagSet.Usage()
		return flag.ErrHelp
	}
	return nil
}

func ensureToken(ctx context.Context) error {
	if globalData.RefreshToken == "" {
		if err := login(ctx, false); err != nil {
			return err
		}
	} else if time.Now().After(globalData.TokenExpiry) {
		if err := refreshToken(ctx); err != nil {
			return err
		}
	}
	return nil
}

func printDump(name string, ciphers []*Cipher, getCipherStrings func(Cipher) []CipherString, fieldNames []string, dumpformat string) error {
	dump, err := gatherDump(ciphers, getCipherStrings)
	if err != nil {
		return err
	}

	switch dumpformat {
	case "csv":
		// write csv to stdout with encoding/csv
		writer := csv.NewWriter(os.Stdout)
		writer.Comma = '\t'
		fmt.Printf("# %s:\n", name)
		writer.Write(fieldNames)
		writer.WriteAll(dump)
		writer.Flush()
	case "json":
		json.NewEncoder(os.Stdout).Encode(dump)
	default:
		// error
		return fmt.Errorf("unknown dump format: %q", dumpformat)
	}

	return nil
}

func gatherDump(ciphers []*Cipher, getCipherStrings func(Cipher) []CipherString) ([][]string, error) {
	var lines [][]string

	// decrypt all ciphers in parallel
	errs, _ := errgroup.WithContext(context.Background())
	var mu sync.Mutex

	for _, cipher := range ciphers {
		// make cipher acccessible to the goroutine
		cipher := cipher
		errs.Go(func() error {
			decryptedCiphers, err := secrets.decryptListStr(cipher.OrganizationID, getCipherStrings(*cipher)...)
			if err != nil {
				secrets.decryptListStr(cipher.OrganizationID, getCipherStrings(*cipher)...)
				return nil
			}

			mu.Lock()
			lines = append(lines, decryptedCiphers)
			mu.Unlock()

			return nil
		})
	}

	if err := errs.Wait(); err != nil {
		return nil, err
	} else {
		return lines, nil
	}
}
