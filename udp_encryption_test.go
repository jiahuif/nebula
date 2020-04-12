package nebula

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	outsideCipher = mustCreateChacha20Cipher(defaultPassword)
}

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

func TestCiphers(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	chacha, err := chacha20poly1305.NewX(make([]byte, 32))
	for _, tc := range []struct {
		name string
		c    cipher.AEAD
	}{
		{"AES", aesGCM},
		{"XChaCha20-Poly1305", chacha},
	} {
		ch := tc.c
		fmt.Printf("%v NonceSize=%d Overhead=%d\n", tc.name, ch.NonceSize(), ch.Overhead())
		if outsideMtu-mtu < ch.NonceSize()+ch.NonceSize() {
			t.Fatal("insufficient padding")
		}
	}
}
