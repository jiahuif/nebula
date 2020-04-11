package nebula

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptDecrypt(t *testing.T) {
	b := []byte("1145141919810")
	ct := encryptOutside(b)
	pt, err := decryptOutside(ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, b) {
		t.Fatal("incorrect result")
	}
}

func TestInvalidDecrypt(t *testing.T) {
	for _, b := range [][]byte{
		make([]byte, chacha20poly1305.NonceSizeX-1),
		make([]byte, chacha20poly1305.NonceSizeX),
	} {
		_, err := decryptOutside(b)
		if err == nil {
			t.Fatal("should return error")
		}
	}
}
