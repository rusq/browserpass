package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"
)

func copyFile(dst, src string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, in)
}

// copyToTemp copies the file to temporary location and returns the resulting
// filepath.
func copyToTemp(src string) (string, error) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		log.Println(err)
		return "", err
	}
	f.Close()

	_, err = copyFile(f.Name(), src)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}
