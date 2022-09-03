package main

import (
	"bytes"
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const maxBufSz = 1 << 30

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

func chromeInit(useOpenSSL bool) (*Chrome, error) {
	return &Chrome{}, nil
}

func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[maxBufSz]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func (c *Chrome) decryptField(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte("v10")) {
		return nil, errors.New("unsupported method")
	}
	var dataIn = &windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob
	if err := windows.CryptUnprotectData(dataIn, nil, nil, 0, nil, 0, &dataOut); err != nil {
		return nil, err
	}
	d := make([]byte, dataOut.Size)
	copy(d, (*[maxBufSz]byte)(unsafe.Pointer(&dataOut.Size))[:])
	_, err := windows.LocalFree(windows.Handle(*dataOut.Data))
	return d, err
}
