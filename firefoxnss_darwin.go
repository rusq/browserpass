package main

import (
	"github.com/rusq/browserpass/nss"
)

const (
	cFailure = -1
	cSuccess = 0
)

func initFirefox() (*FirefoxNSS, error) {
	ns, err := nss.New3FromPath()
	if err != nil {
		return nil, err
	}
	ff := &FirefoxNSS{
		nss: ns,
	}
	return ff, nil
}
