package main

// LoginInfo is a structure containing all necessary values.
type LoginInfo struct {
	Profile   string
	Origin    string
	Username  string
	Encrypted []byte
	Password  string

	Err error // will contain processing error if any
}

// WithError sets the error on LoginInfo.
func (li *LoginInfo) WithError(err error) *LoginInfo {
	li.Err = err
	return li
}
