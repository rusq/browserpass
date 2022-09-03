package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/rusq/dlog"
	"github.com/rusq/gonss3"
)

type BaseFirefox struct{}

// Firefox is a firefox with a go decoding.
type Firefox struct {
	BaseFirefox

	files []string
}

type FirefoxLogins struct {
	NextID                           int64         `json:"nextId"`
	Logins                           []Login       `json:"logins"`
	PotentiallyVulnerablePasswords   []interface{} `json:"potentiallyVulnerablePasswords"`
	DismissedBreachAlertsByLoginGUID interface{}   `json:"dismissedBreachAlertsByLoginGUID"`
	Version                          int64         `json:"version"`
}

type Login struct {
	ID                  int64       `json:"id"`
	Hostname            string      `json:"hostname"`
	HTTPRealm           interface{} `json:"httpRealm"`
	FormSubmitURL       string      `json:"formSubmitURL"`
	UsernameField       string      `json:"usernameField"`
	PasswordField       string      `json:"passwordField"`
	EncryptedUsername   string      `json:"encryptedUsername"`
	EncryptedPassword   string      `json:"encryptedPassword"`
	GUID                string      `json:"guid"`
	EncType             int64       `json:"encType"`
	TimeCreated         int64       `json:"timeCreated"`
	TimeLastUsed        int64       `json:"timeLastUsed"`
	TimePasswordChanged int64       `json:"timePasswordChanged"`
	TimesUsed           int64       `json:"timesUsed"`
}

type DecryptError struct {
	msg      string
	nssError error
}

var errNothingToDo = errors.New("nothing to do")

func (e *DecryptError) Error() string {
	return fmt.Sprintf("%s: %s", e.msg, e.nssError)
}
func newDecryptError(msg string, err error) *DecryptError {
	return &DecryptError{msg, err}
}

// loginFiles returns the list of profile login data files
func (f *BaseFirefox) loginFiles() ([]string, error) {
	files, err := filepath.Glob(f.dbPathGlob())
	dlog.Debugf("loginFiles() error: %s", err)
	return files, err
}

func NewFirefox() (*Firefox, error) {
	f := &Firefox{}
	return f, nil
}

func (f *Firefox) Decrypt() <-chan *LoginInfo {
	results := make(chan *LoginInfo)
	go func() {
		defer close(results)
		files, err := f.loginFiles()
		if err != nil {
			results <- &LoginInfo{Err: err}
			return
		}
		for _, file := range files {
			li := &LoginInfo{Profile: profileName(file)}
			pf, err := gonss3.New(filepath.Dir(file), []byte{})
			if err != nil {
				results <- li.WithError(err)
				continue
			}
			data, err := ioutil.ReadFile(file)
			if err != nil {
				results <- li.WithError(err)
				continue
			}
			var logins FirefoxLogins
			if err := json.Unmarshal(data, &logins); err != nil {
				results <- li.WithError(err)
				continue
			}
			if len(logins.Logins) == 0 {
				results <- li.WithError(err)
				continue
			}

			for _, login := range logins.Logins {
				li := &LoginInfo{Profile: profileName(file)}
				if name, err := pf.DecryptField(login.EncryptedUsername); err != nil {
					li.Username = errorField
				} else {
					li.Username = string(name)
				}
				if pass, err := pf.DecryptField(login.EncryptedPassword); err != nil {
					li.Password = errorField
				} else {
					li.Password = string(pass)
				}
				li.Origin = login.Hostname
				results <- li
			}
		}
	}()

	return results
}
