package main

import (
	"os"
	"path/filepath"
)

func (BaseFirefox) dbPathGlob() string {
	return filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox", "Profiles", "*", "logins.json")
}
