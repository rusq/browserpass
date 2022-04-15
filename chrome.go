package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// Chrome implements Chrome browser password decryption.
type Chrome struct {
	key []byte

	data chan *LoginInfo // data channel
	iv   []byte

	openSSL bool
}

// NewChrome creates a new Chrome password dumper.  `useOpenSSL` allows
// to use openssl binary instead of built in crypto library, if supported.
func NewChrome(useOpenSSL bool) (*Chrome, error) {
	c, err := chromeInit(useOpenSSL)
	if err != nil {
		return nil, err
	}

	return c, nil
}

// loginFiles returns the list of profile login data files
func (c *Chrome) loginFiles() ([]string, error) {
	return filepath.Glob(c.dbPathGlob())
}

func (c *Chrome) processFile(results chan<- *LoginInfo, profileName string, dbfile string) error {
	const stmt = "SELECT origin_url, username_value, password_value FROM logins"
	fi, err := os.Stat(dbfile)
	if err != nil {
		return err
	}
	if fi.Size() == 0 {
		return fmt.Errorf("empty database file for profile %q: %q", profileName, dbfile)
	}
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return err
	}
	rows, err := db.Query(stmt)
	if err != nil {
		return fmt.Errorf("profile: %s, error: %s", profileName, err)
	}
	defer rows.Close()

	for rows.Next() {
		var origin, username string
		var encryptedPass = make([]byte, passBufSz)
		if err := rows.Scan(&origin, &username, &encryptedPass); err != nil {
			results <- &LoginInfo{Err: err}
			return err
		}
		passw, err := c.decryptField(encryptedPass)
		if err != nil {
			passw = []byte(errorField)
		}
		results <- &LoginInfo{
			Profile:  profileName,
			Origin:   origin,
			Username: username,
			Password: string(passw),
			Err:      err}
	}
	if err := rows.Err(); err != nil {
		results <- &LoginInfo{Err: err}
		return err
	}
	return nil
}

func (c *Chrome) Decrypt() <-chan *LoginInfo {
	results := make(chan *LoginInfo)

	go func() {
		defer close(results)
		files, err := c.loginFiles()
		if err != nil {
			results <- &LoginInfo{Err: err}
			return
		}
		for _, file := range files {
			tmpFile, err := copyToTemp(file)
			if err != nil {
				log.Println(err)
				return
			}
			defer os.Remove(tmpFile)

			if err := c.processFile(results, profileName(file), tmpFile); err != nil {
				log.Println(err)
				return
			}
		}
	}()
	return results
}
