package nebula

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const outsideMtu = mtu + 128

var outsideCipher = mustCreateChacha20Cipher("nebula")

func mustCreateChacha20Cipher(password string) cipher.AEAD {
	key := sha256.Sum256([]byte(password))
	c, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		panic(err)
	}
	return c
}

func encryptOutside(buf []byte) []byte {
	ns := outsideCipher.NonceSize()
	out := make([]byte, ns+len(buf)+outsideCipher.Overhead())
	nonce := out[:ns]
	_, _ = rand.Read(nonce)
	ct := outsideCipher.Seal(out[ns:ns], nonce, buf, nil)
	return out[:ns+len(ct)]
}

func decryptOutside(buf []byte) ([]byte, error) {
	ns := outsideCipher.NonceSize()
	if len(buf) < ns {
		return nil, io.ErrUnexpectedEOF
	}
	return outsideCipher.Open(buf[ns:ns], buf[:ns], buf[ns:], nil)
}
