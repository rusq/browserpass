package nss

import "unsafe"

// string functions

func goString(ptr uintptr) string {
	return goStringN(ptr, maxStringLength)
}

func goStringN(ptr uintptr, n int) string {
	return string(goByteN(ptr, n))
}

func goByteN(ptr uintptr, n int) []byte {
	var bb = make([]byte, 0, n)
	for i := 0; i < n; i++ {
		b := *(*byte)(unsafe.Pointer(ptr + uintptr(i)))
		if b == byte(0) { // end of C-string
			break
		}
		bb = append(bb, b)
	}

	//val := syscall.UTF16ToString(*(*[]uint16)(unsafe.Pointer(ptr)))
	return bb
}
