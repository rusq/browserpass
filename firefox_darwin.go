package main

import (
	"os"
	"path/filepath"
)

func (BaseFirefox) dbPathGlob() string {
	return filepath.Join(os.Getenv("HOME"), "Library", "ApplicationSupport", "Firefox", "Profiles", "*", "logins.json")
}
