package main

import (
	"fmt"

	"github.com/rusq/browserpass/nss"
)

func initFirefox() (*FirefoxNSS, error) {
	nss, err := nss.New3("nss3.dll")
	if err != nil {
		return nil, err
	}
	if err := nss.NSS_Init("sql:C:/Users/rusq/AppData/Roaming/Mozilla/FirefoxNSS/Profiles/thatdsnb.default-release"); err != nil {
		return nil, err
	}
	defer nss.Shutdown()
	if err := nss.Auth(""); err != nil {
		return nil, err
	}
	ff := &FirefoxNSS{nss: nss}

	data, err := nss.Decode64([]byte("5QjdGOG9SlgDSXW6L2zWLpemg/ZGAgDT5Z1Lz8/d1FugVI6WtXuRiq8t2lUVP8YUT0ciQFkFD2CgprRa"))
	if err != nil {
		return nil, err
	}
	fmt.Println(data)

	return ff, nil
}
