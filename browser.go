package main

import (
	"path/filepath"
	"strings"
)

const errorField = "<error>"

func profileName(fullpath string) string {
	splitPath := strings.Split(fullpath, string(filepath.Separator))
	return splitPath[len(splitPath)-2]
}
