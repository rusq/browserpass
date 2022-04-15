package nss

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func Test_findFile(t *testing.T) {
	f, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(f)
	}
	f.Close()
	defer os.Remove(f.Name())

	dir, file := filepath.Split(f.Name())

	type args struct {
		name      string
		locations []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"1", args{file, []string{dir}}, f.Name(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findFile(tt.args.name, tt.args.locations)
			if (err != nil) != tt.wantErr {
				t.Errorf("BaseFirefox.findLibrary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BaseFirefox.findLibrary() = %v, want %v", got, tt.want)
			}
		})
	}
}

