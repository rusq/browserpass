// build: darwin

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const openSSLcmdv10 = "openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>%s"

type decryptFunc func(ct []byte, iv []byte, key []byte) ([]byte, error)

func (Chrome) dbPathGlob() string {
	return filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Google", "Chrome", "*", "Login Data")
}

func chromeDecryptionKey() (string, error) {
	const prefix = "password: \""
	cmd := exec.Command("security", "find-generic-password", "-w", "-ga", "Chrome")
	log.Print("trying to get the Chrome key from keychain, please follow the prompts")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error getting credentials from keychain: %s [%s]", err.Error(), string(out))
	}

	pwd := strings.Trim(string(out), "\n")
	if len(pwd) == 0 {
		return "", errors.New("key not found in keychain")
	}
	return pwd, nil
}

func chromeInit(useOpenSSL bool) (*Chrome, error) {
	key, err := chromeDecryptionKey()
	if err != nil {
		return nil, err
	}
	derivedKey := pbkdf2.Key([]byte(key), []byte("saltysalt"), 1003, 16, sha1.New)
	c := &Chrome{
		key:     derivedKey,
		iv:      bytes.Repeat([]byte(" "), 16),
		openSSL: useOpenSSL,
	}
	return c, nil
}

func (c *Chrome) decryptField(ct []byte) ([]byte, error) {
	const (
		// https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm
		// Prefix for cypher text returned by current encryption version.  We
		// prefix the cypher text with this string so that future data
		// migration can detect this and migrate to different encryption
		// without data loss.
		v10 = "v10"
		v11 = "v11"
	)
	if len(ct) == 0 {
		return []byte{}, nil
	}

	ver := string(ct[:len(v10)])
	var decryptor decryptFunc
	switch ver {
	default: // no encryption
		return ct, nil
	case v10:
		if c.openSSL {
			decryptor = c.openSSLdecryptv10
			break
		}
		decryptor = c.decryptv10
	case v11:
		return nil, errors.New("unsupported password version")
	}

	return decryptor(ct[len(v10):], c.iv, c.key)
}

func (c *Chrome) decryptv10(ct []byte, iv []byte, key []byte) ([]byte, error) {
	if len(ct) == 0 {
		return []byte{}, nil
	}
	if len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ct, ct)
	return pkcs5trim(ct), nil
}

func (c *Chrome) openSSLdecryptv10(ct []byte, iv []byte, key []byte) ([]byte, error) {
	if len(ct) == 0 {
		return []byte{}, nil
	}

	hexKey := hex.EncodeToString(key)
	hexEncPassword := base64.StdEncoding.EncodeToString(ct)
	ivHex := hex.EncodeToString(iv)
	cmd := fmt.Sprintf(openSSLcmdv10, ivHex, hexKey, hexEncPassword, os.DevNull)

	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		return nil, errors.New("unable to decipher password")
	}
	return output, nil
}

func pkcs5trim(pt []byte) []byte {
	padSz := pt[len(pt)-1]
	return pt[:len(pt)-int(padSz)]
}
