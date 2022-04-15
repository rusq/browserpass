// +build !windows

package nss

/* #cgo LDFLAGS: -ldl

#include <stdlib.h>
#include <dlfcn.h>
#include "nss.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"
)

//https://github.com/unode/firefox_decrypt/blob/master/firefox_decrypt.py#L371
const nssname = "libnss3.dylib"

var locations = []string{
	"", // Current directory or system lib finder
	"/Applications/Firefox.app/Contents/MacOS",
	"/usr/local/lib/nss",
	"/usr/local/lib",
	"/opt/local/lib/nss",
	"/sw/lib/firefox",
	"/sw/lib/mozilla",
	"/usr/local/opt/nss/lib", // nss installed with Brew on Darwin
	"/opt/pkg/lib/nss",       // installed via pkgsrc

}

func new3(dllPath string) (*NSS, error) {
	var libName *C.char = C.CString(dllPath)
	defer C.free(unsafe.Pointer(libName))

	handle := C.dlopen(libName, C.RTLD_LAZY)
	if handle == nil {
		reason := C.GoString(C.dlerror())
		return nil, fmt.Errorf("%s\ntry running `export DYLD_LIBRARY_PATH=%s` and restart the application.", reason, filepath.Dir(dllPath))
	}

	ns := &NSS{nss3: uintptr(handle)}
	if err := ns.loadSymbols(); err != nil {
		return nil, err
	}
	return ns, nil
}

func (ns *NSS) loadSymbols() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	ns._nssInit = mustPtr(getSymbol(ns.nss3, "NSS_Init"))
	ns._nssShutdown = mustPtr(getSymbol(ns.nss3, "NSS_Shutdown"))
	ns._pk11GetInternalKeySlot = mustPtr(getSymbol(ns.nss3, "PK11_GetInternalKeySlot"))
	ns._pk11FreeSlot = mustPtr(getSymbol(ns.nss3, "PK11_FreeSlot"))
	ns._pk11CheckUserPassword = mustPtr(getSymbol(ns.nss3, "PK11_CheckUserPassword"))
	ns._pk11SDRDecrypt = mustPtr(getSymbol(ns.nss3, "PK11SDR_Decrypt"))
	ns._secitemZfreeItem = mustPtr(getSymbol(ns.nss3, "SECITEM_ZfreeItem"))

	ns._portGetError = mustPtr(getSymbol(ns.nss3, "PORT_GetError"))
	ns._prErrorToName = mustPtr(getSymbol(ns.nss3, "PR_ErrorToName"))
	ns._prErrorToString = mustPtr(getSymbol(ns.nss3, "PR_ErrorToString"))
	return
}

func getSymbol(hLib uintptr, name string) (uintptr, error) {
	//https://github.com/coreos/pkg/blob/master/dlopen/dlopen.go
	ref := C.CString(name)
	defer C.free(unsafe.Pointer(ref))

	C.dlerror()
	p := C.dlsym(unsafe.Pointer(hLib), ref)
	err := C.dlerror()
	if err != nil {
		return 0, fmt.Errorf("error resolving symbol %q: %v", name, errors.New(C.GoString(err)))
	}

	return uintptr(p), nil
}

func (ns *NSS) Auth(password string) error {
	slot, err := ns.PK11_GetInternalKeySlot()
	if err != nil {
		return err
	}
	defer ns.PK11_FreeSlot(slot)
	if err := ns.PK11_CheckUserPassword(slot, password); err != nil {
		return err
	}
	return nil
}

func (ns *NSS) decode(data []byte) ([]byte, error) {
	in := GoSECItem{0, data}
	out := GoSECItem{}

	if err := ns.PK11SDR_Decrypt(&in, &out); err != nil {
		return nil, fmt.Errorf("PK11SDR_Decrypt %w: [% x]", err, data)
	}
	//C.GoString((*C.uchar)(unsafe.Pointer(out.data)))
	return out.Data, nil
}

func mustPtr(p uintptr, err error) uintptr {
	if err != nil {
		panic(err)
	}
	return p
}

func (ns *NSS) close() error {
	_ = ns.Shutdown()
	C.dlerror()
	C.dlclose(unsafe.Pointer(ns.nss3))
	e := C.dlerror()
	if e != nil {
		return fmt.Errorf("error closing library: %v", errors.New(C.GoString(e)))
	}

	return nil
}

func (ns *NSS) NSS_Init(profilePath string) error {
	profile := C.CString(profilePath)
	defer C.free(unsafe.Pointer(profile))
	rv := C._NSS_Init(unsafe.Pointer(ns._nssInit), profile)
	if rv != C.SECSuccess {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) NSS_Shutdown() error {
	if rv := C._NSS_Shutdown(unsafe.Pointer(ns._nssShutdown)); rv != C.SECFailure {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) PK11_GetInternalKeySlot() (uintptr, error) {
	rv := C._PK11_GetInternalKeySlot(unsafe.Pointer(ns._pk11GetInternalKeySlot))
	if rv == nil {
		return 0, ns.getError()
	}
	return uintptr(rv), nil
}

func (ns *NSS) PK11_FreeSlot(slot uintptr) {
	C._PK11_FreeSlot(unsafe.Pointer(ns._pk11FreeSlot), unsafe.Pointer(slot))
}

func (ns *NSS) PK11_CheckUserPassword(slot uintptr, passwd string) error {
	cPass := C.CString(passwd)
	defer C.free(unsafe.Pointer(cPass))
	rv := C._PK11_CheckUserPassword(
		unsafe.Pointer(ns._pk11CheckUserPassword),
		unsafe.Pointer(slot),
		cPass,
	)
	if rv != C.SECSuccess {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) PK11SDR_Decrypt(data, result *GoSECItem) error {
	siData := data.SECItem()

	cdata := C.new_SECItem(
		(C.SECItemType)(siData.SECItemType),
		(*C.uchar)(unsafe.Pointer(siData.data)),
		(C.uint)(siData.len),
	)
	defer C.free(unsafe.Pointer(cdata))

	cresult := C.new_SECItem(0, (*C.uchar)(unsafe.Pointer(nil)), 0)
	//defer C.free(unsafe.Pointer(cresult))
	defer ns.SECITEM_ZfreeItem(cresult, true)

	rv := C._PK11SDR_Decrypt(
		unsafe.Pointer(ns._pk11SDRDecrypt),
		cdata,
		cresult,
		nil,
	)
	if rv != C.SECSuccess {
		return ns.getError()
	}
	//C.alterme(cdata)
	//spew.Dump(cdata)
	//spew.Dump(cresult)

	*result = *GoSECItemFromCstruct(cresult)

	return nil
}

func (ns *NSS) SECITEM_ZfreeItem(si *C.SECItem, freeItem bool) {
	var prbool C.PRBool
	if freeItem {
		prbool = 1
	}
	C._SECITEM_ZfreeItem(unsafe.Pointer(ns._secitemZfreeItem), si, prbool)
}

func (ns *NSS) getError() error {
	code := C._PORT_GetError(unsafe.Pointer(ns._portGetError))
	name := C._PR_ErrorToName(unsafe.Pointer(ns._prErrorToName), code)
	reason := C._PR_ErrorToString(unsafe.Pointer(ns._prErrorToString), code, 0)

	return &NSSError{int(code), C.GoString(name), C.GoString(reason)}
}
