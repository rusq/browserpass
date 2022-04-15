package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

const (
	chrome  = "c"
	firefox = "f"
)

var browsers = []string{chrome, firefox}

const passBufSz = 512

var (
	browserType = flag.String("b", "", "`browser` to pull the data from.  Browser is 1 character:\n"+
		"\tc\t- Chrome\n\tf\t- Firefox")
	openSSL = flag.Bool("openssl", false, "(chrome) use OpenSSL instead of built-in cryptographic library (slow)")
	mozNSS  = flag.Bool("nss3", false, "(firefox) use Mozilla NSS native library (buggy)")

	verbose = flag.Bool("v", false, "verbose output")
)

// Browser is the interface that each browser must satisfy.  We're not asking
// for too much.
type Browser interface {
	Decrypt() (results <-chan *LoginInfo)
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	var (
		browser Browser
		err     error
	)

	switch *browserType {
	default:
		flag.Usage()
		os.Exit(1)
	case chrome:
		browser, err = NewChrome(*openSSL)
	case firefox:
		if *mozNSS {
			browser, err = NewFirefoxNSS()
		} else {
			browser, err = NewFirefox()
		}
	}
	if err != nil {
		log.Fatal(err)
	}

	results := browser.Decrypt()

	formFormatter(results, *verbose)
}

func formFormatter(results <-chan *LoginInfo, verbose bool) {
	const (
		fmtLoginErr = "\tlogin:\t\t%q\n\terror:\t\t%s\n"
	)

	var buf = bufio.NewWriter(os.Stdout)
	defer buf.Flush()

	var prev string
	for res := range results {
		var decryptErr bool
		if res.Err != nil {
			log.Printf("failure on profile %q: %s", res.Profile, res.Err)
			if _, ok := res.Err.(*DecryptError); !ok {
				continue
			}
			decryptErr = true
		}
		if res.Username == "" && res.Password == "" {
			continue
		}
		if prev != res.Profile {
			fmt.Fprintf(buf, "\n<PROFILE: %s>\n", res.Profile)
			prev = res.Profile
		}
		fmt.Fprintln(buf, res.Origin)
		if res.Err != nil && !decryptErr {
			fmt.Fprintf(buf, fmtLoginErr, res.Username, res.Err)
			continue
		}
		if verbose {
			fmt.Fprintf(buf, "\tlogin:\t\t%q\n\tpassword:\t%q\n\tct:\t\t%v\n", res.Username, res.Password, res.Encrypted)
		} else {
			fmt.Fprintf(buf, "\tlogin:\t\t%q\n\tpassword:\t%q\n", res.Username, res.Password)
		}

	}
}
