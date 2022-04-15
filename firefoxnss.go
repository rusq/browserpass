package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/rusq/browserpass/nss"
)

type FirefoxNSS struct {
	BaseFirefox
	nss *nss.NSS

	files []string
}

// NewFirefoxNSS creates a new firefox password dumper.
func NewFirefoxNSS() (*FirefoxNSS, error) {
	ff, err := initFirefox()
	if err != nil {
		return nil, err
	}
	files, err := ff.loginFiles()
	if err != nil {
		return nil, err
	}
	ff.files = files

	return ff, nil
}

func (ff *FirefoxNSS) Decrypt() <-chan *LoginInfo {
	results := make(chan *LoginInfo)

	go func() {
		defer close(results)
		for _, f := range ff.files {
			li := &LoginInfo{Profile: profileName(f)}
			if err := ff.nss.Init("sql:" + filepath.Dir(f)); err != nil {
				results <- li.WithError(err)
				continue
			}
			defer ff.nss.Shutdown()
			if err := ff.nss.Auth(""); err != nil {
				results <- li.WithError(err)
				continue
			}
			if err := ff.processFile(results, profileName(f), f); err != nil {
				if errors.Is(err, errNothingToDo) {
					continue
				}
				results <- li.WithError(err)
				return
			}
			ff.nss.Shutdown()
		}
	}()
	return results
}

func (ff *FirefoxNSS) processFile(results chan<- *LoginInfo, profileName, dbfile string) error {
	data, err := ioutil.ReadFile(dbfile)
	if err != nil {
		return err
	}
	logins := FirefoxLogins{}
	if err := json.Unmarshal(data, &logins); err != nil {
		return err
	}

	if len(logins.Logins) == 0 {
		return errNothingToDo
	}
	for _, login := range logins.Logins {
		data := &LoginInfo{
			Profile:   profileName,
			Origin:    login.Hostname,
			Username:  login.EncryptedUsername,
			Encrypted: []byte(login.EncryptedPassword),
			Password:  login.EncryptedPassword,
			Err:       nil,
		}
		results <- ff.decryptInfo(data)
	}
	return nil
}

func (ff *FirefoxNSS) decryptInfo(info *LoginInfo) *LoginInfo {
	const errmsg = "%s decode error for %q"
	var err error
	result := &LoginInfo{
		Profile: info.Profile,
		Origin:  info.Origin,
	}
	result.Username, err = ff.nss.DecodeString64(info.Username)
	if err != nil {
		result.Username = "<error>"
		result.Err = newDecryptError(fmt.Sprintf(errmsg, "username", info.Profile), err)
	}
	result.Password, err = ff.nss.DecodeString64(info.Password)
	if err != nil {
		result.Password = "<error>"
		result.Err = newDecryptError(fmt.Sprintf(errmsg, "password", info.Profile), err)
	}
	return result
}

// Close deinitialises library.
func (ff *FirefoxNSS) Close() error {
	return ff.nss.Close()
}
