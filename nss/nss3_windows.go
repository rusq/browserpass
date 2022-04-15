package nss

import (
	"syscall"
	"unsafe"
)

const nssname = "nss3.dll"

var locations = []string{
	"", // Current directory or system lib finder
	"C:\\Program Files (x86)\\Mozilla Firefox",
	"C:\\Program Files (x86)\\Mozilla Thunderbird",
	"C:\\Program Files (x86)\\Nightly",
	// On windows 32bit these folders can also be 32bit
	"C:\\Program Files\\Mozilla Firefox",
	"C:\\Program Files\\Mozilla Thunderbird",
	"C:\\Program Files\\Nightly",
}

func (ns *NSS) loadSymbols() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	ns._nssInit = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "NSS_Init"))
	ns._nssShutdown = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "NSS_Shutdown"))
	ns._pk11GetInternalKeySlot = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PK11_GetInternalKeySlot"))
	ns._pk11FreeSlot = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PK11_FreeSlot"))
	ns._pk11CheckUserPassword = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PK11_CheckUserPassword"))
	ns._pk11SDRDecrypt = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PK11SDR_Decrypt"))
	ns._secitemZfreeItem = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "SECITEM_ZfreeItem"))

	ns._portGetError = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PORT_GetError"))
	ns._prErrorToName = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PR_ErrorToName"))
	ns._prErrorToString = mustPtr(syscall.GetProcAddress(syscall.Handle(ns.nss3), "PR_ErrorToString"))
	return nil
}

func mustPtr(p uintptr, err error) uintptr {
	if err != nil {
		panic(err)
	}
	return p
}

// new3 creates a new abstraction layer over the NSS library at `dllPath`
func new3(dllPath string) (*NSS, error) {
	lib, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		return nil, err
	}

	n := &NSS{nss3: uintptr(lib)}
	if err := n.loadSymbols(); err != nil {
		return nil, err
	}
	return n, nil
}

func (ns *NSS) NSS_Init(profilePath string) error {
	rv, _, codeErr := syscall.Syscall(ns._nssInit, 1, uintptr(unsafe.Pointer(syscall.StringBytePtr(profilePath))), 0, 0)
	if codeErr != 0 {
		abort("NSS_Init", codeErr)
	}
	if rv != SECSuccess {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) NSS_Shutdown() error {
	rv, _, codeErr := syscall.Syscall(ns._nssShutdown, 0, 0, 0, 0)
	if codeErr != 0 {
		abort("NSS_Shutdown", codeErr)
	}
	if rv != SECSuccess {
		return ns.getError()
	}
	return nil
}

// Shutdown deinitialises NSS
func (ns *NSS) close() error {
	defer syscall.FreeLibrary(syscall.Handle(ns.nss3))

	return ns.NSS_Shutdown()
}

func (ns *NSS) Auth(password string) error {
	keyslot, _, codeErr := syscall.Syscall(ns._pk11GetInternalKeySlot, 0, 0, 0, 0)
	if codeErr != 0 {
		abort("PK11_GetInternalKeySlot", codeErr)
	}
	if keyslot == 0 {
		return ns.getError()
	}
	defer syscall.Syscall(ns._pk11FreeSlot, 1, keyslot, 0, 0)

	// empty password
	rv, _, codeErr := syscall.Syscall(
		ns._pk11CheckUserPassword, 2,
		keyslot, uintptr(unsafe.Pointer(syscall.StringBytePtr(password))),
		0)
	if codeErr != 0 {
		abort("PK11_CheckUserPassword", codeErr)
	}
	if rv != SECSuccess {
		return ns.getError()
	}

	return nil
}

func (ns *NSS) decode(data []byte) ([]byte, error) {
	// inp := SECItem{0, uintptr(unsafe.Pointer(&ct[0])), uint32(bytelen)}
	inp := NewSecItem(0, data)
	out := SECItem{}
	defer ns.SECITEM_ZfreeItem(&out, false)

	if err := ns.PK11SDR_Decrypt(inp, &out, 0); err != nil {
		return nil, err
	}

	return goByteN(out.data, int(out.len)), nil
}

func (ns *NSS) PK11SDR_Decrypt(pIn, pOut *SECItem, unimplemented uintptr) error {
	var pcount uintptr = 3
	rv, _, errCode := syscall.Syscall(ns._pk11SDRDecrypt, pcount, uintptr(unsafe.Pointer(pIn)), uintptr(unsafe.Pointer(pOut)), 0)
	if errCode != 0 {
		abort("PK11SDR_Decrypt", errCode)
	}
	if rv != SECSuccess {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) SECITEM_ZfreeItem(si *SECItem, b bool) error {
	var (
		pcount  uintptr = 2
		boolVar uintptr = 0 // false
	)
	if b == true {
		boolVar = 1
	}
	rv, _, errCode := syscall.Syscall(ns._secitemZfreeItem, pcount, uintptr(unsafe.Pointer(si)), boolVar, 0)
	if errCode != 0 {
		abort("SECITEM_ZfreeItem", errCode)
	}
	if rv != SECSuccess {
		return ns.getError()
	}
	return nil
}

func (ns *NSS) getError() error {
	code, _, err := syscall.Syscall(ns._portGetError, 0, 0, 0, 0)
	if err != 0 {
		abort("PORT_GetError", err)
	}

	namePtr, _, err := syscall.Syscall(ns._prErrorToName, 1, uintptr(code), 0, 0)
	if err != 0 {
		abort("PR_ErrorToName", err)
	}
	reason, _, err := syscall.Syscall(ns._prErrorToString, 2, uintptr(code), 0, 0)
	if err != 0 {
		abort("PR_ErrorToString", err)
	}
	return &NSSError{int(code), goString(namePtr), goString(reason)}

}
