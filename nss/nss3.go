package nss

/*
#include "nss.h"
*/
import "C"
import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"
)

const (
	SECSuccess    = 0
	SECFailed     = -1
	SECWouldBlock = -2
)

const (
	maxStringLength = 1048576 //to avoid buffer overflow
)

type SECItemType int

// SECITEM types.
const (
	SIBuffer SECItemType = iota
)

type SECItem struct {
	SECItemType uint32
	data        uintptr
	len         uint32
}

type GoSECItem struct {
	Type SECItemType
	Data []byte
}

func (gsi *GoSECItem) SECItem() *SECItem {
	si := SECItem{
		SECItemType: uint32(gsi.Type),
		data:        uintptr(unsafe.Pointer(&gsi.Data[0])),
		len:         uint32(len(gsi.Data)),
	}
	return &si
}

func GoSECItemFromCstruct(si *C.SECItem) *GoSECItem {
	gsi := GoSECItem{
		Type: SECItemType((uintptr)(si._type)),
		Data: C.GoBytes(
			unsafe.Pointer(si.data),
			C.int((uintptr)(si.len))),
	}
	return &gsi
}

type NSS struct {
	nss3 uintptr

	profilePath string

	_nssInit                uintptr
	_nssShutdown            uintptr
	_pk11GetInternalKeySlot uintptr
	_pk11FreeSlot           uintptr
	_pk11CheckUserPassword  uintptr
	_pk11SDRDecrypt         uintptr
	_secitemZfreeItem       uintptr

	// error handling
	_portGetError    uintptr
	_prErrorToName   uintptr
	_prErrorToString uintptr
}

type NSSError struct {
	Code   int
	Name   string
	Reason string
}

var encoding = base64.StdEncoding

func (e NSSError) Error() string {
	return fmt.Sprintf("NSS error: code(%d): %s, %s\n", e.Code, e.Name, e.Reason)
}

func abort(funcname string, err error) {
	panic(fmt.Sprintf("%s failed: %v", funcname, err))
}

// New3 creates a new abstraction layer over the NSS library at `dllPath`
func New3(dllPath string) (*NSS, error) {
	return new3(dllPath)
}

func New3FromPath() (*NSS, error) {
	// nssname and locations must be defined in the concrete OS go file.
	lib, err := findFile(nssname, locations)
	if err != nil {
		return nil, err
	}
	return New3(lib)
}

// Init opens the profile.
func (ns *NSS) Init(profilePath string) error {
	if ns.profilePath != "" {
		return errors.New("profile is already open")
	}
	if err := ns.NSS_Init(profilePath); err != nil {
		return err
	}
	ns.profilePath = profilePath
	return nil
}

// Shutdown closes the profile
func (ns *NSS) Shutdown() error {
	if ns.profilePath == "" {
		return nil
	}
	if err := ns.NSS_Shutdown(); err != nil {
		return err
	}
	ns.profilePath = ""
	return nil
}

func (ns *NSS) DecodeString64(str64 string) (string, error) {
	data, err := encoding.DecodeString(str64)
	if err != nil {
		return "", err
	}
	bin, err := ns.Decode(data)
	if err != nil {
		return "", err
	}
	return string(bin), nil
}

// decode decodes a chunk of base64 encoded data
func (ns *NSS) Decode64(data64 []byte) ([]byte, error) {
	ct := make([]byte, encoding.DecodedLen(len(data64)))
	n, err := encoding.Decode(ct, data64)
	if err != nil {
		return nil, err
	}

	return ns.Decode(ct[:n])
}

func (ns *NSS) Decode(data []byte) ([]byte, error) {
	return ns.decode(data)
}

func NewSecItem(typ SECItemType, ct []byte) *SECItem {
	si := SECItem{
		uint32(typ),
		uintptr(unsafe.Pointer(&ct[0])),
		uint32(len(ct)),
	}
	return &si
}

func findFile(name string, locations []string) (string, error) {
	var file string
	found := false
	for _, dir := range locations {
		file = filepath.Join(dir, name)
		_, err := os.Stat(file)
		if err == nil {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("library %s not found", name)
	}
	return file, nil
}

func (ns *NSS) Close() error {
	return ns.close()
}
