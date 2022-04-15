package main

import (
	"bytes"
	"reflect"
	"testing"
)

func must(b []byte, e error) []byte {
	if e != nil {
		panic(e)
	}
	return b
}

var chromeIV = bytes.Repeat([]byte(" "), 16)

func TestChrome_decryptv10(t *testing.T) {
	type fields struct {
		key     []byte
		data    chan *LoginInfo
		openSSL bool
	}
	type args struct {
		ct  []byte
		iv  []byte
		key []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"1",
			fields{},
			args{
				ct:  []byte{0x95, 0xb, 0x51, 0x16, 0x69, 0xaf, 0xd9, 0xc5, 0xeb, 0x29, 0x4a, 0x6f, 0xd4, 0xf0, 0x6d, 0x51},
				iv:  chromeIV,
				key: []byte{0x49, 0x94, 0x3d, 0x44, 0x11, 0xe2, 0x16, 0x98, 0x7, 0x4b, 0xde, 0xd9, 0xa0, 0x55, 0xd3, 0x3d},
			},
			[]byte("Passw0rd*/*"), false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Chrome{
				key:     tt.fields.key,
				data:    tt.fields.data,
				openSSL: tt.fields.openSSL,
			}
			got, err := c.decryptv10(tt.args.ct, tt.args.iv, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Chrome.decryptv10() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Chrome.decryptv10() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChrome_openSSLdecryptv10(t *testing.T) {
	type fields struct {
		key     []byte
		data    chan *LoginInfo
		openSSL bool
	}
	type args struct {
		ct  []byte
		iv  []byte
		key []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{"ok",
			fields{},
			args{ct: []byte{0x95, 0xb, 0x51, 0x16, 0x69, 0xaf, 0xd9, 0xc5, 0xeb, 0x29, 0x4a, 0x6f, 0xd4, 0xf0, 0x6d, 0x51},
				iv:  chromeIV,
				key: []byte{0x49, 0x94, 0x3d, 0x44, 0x11, 0xe2, 0x16, 0x98, 0x7, 0x4b, 0xde, 0xd9, 0xa0, 0x55, 0xd3, 0x3d},
			},
			[]byte("Passw0rd*/*"), false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Chrome{
				key:     tt.fields.key,
				data:    tt.fields.data,
				openSSL: tt.fields.openSSL,
			}
			got, err := c.openSSLdecryptv10(tt.args.ct, tt.args.iv, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Chrome.openSSLdecryptv10() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Chrome.openSSLdecryptv10() = %v, want %v", got, tt.want)
			}
		})
	}
}
