package main

import (
	"os"
	"path/filepath"
)

func (Chrome) dbPathGlob() string {
	// localPath, err := getLocalPath()
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(localPath)
	localPath := os.Getenv("LOCALAPPDATA")
	return filepath.Join(localPath, "Google", "Chrome", "User Data", "*", "Login Data")
}

// https://hackerfansofficial.blogspot.com/2019/05/how-to-get-chrome-and-firefox-passwords.html

// func getLocalPath() (string, error) {

// 	var dbLoc [win.MAX_PATH]uint16

// 	if ok := win.SHGetSpecialFolderPath(win.WM_NULL, &dbLoc[0], win.CSIDL_LOCAL_APPDATA, false); !ok {
// 		return "", errors.New("syscall failed")
// 	}

// 	return syscall.UTF16ToString(dbLoc[:]), nil

// }

func chromeDecryptionKey() (string, error) {
	return "", nil
}
