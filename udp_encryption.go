package nebula

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const outsideMtu = mtu + 64
const defaultPassword = "nebula"

var outsideCipher cipher.AEAD

func createChacha20CipherByPassword(password string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(password))
	return chacha20poly1305.NewX(key[:])
}

func mustCreateChacha20Cipher(password string) cipher.AEAD {
	c, err := createChacha20CipherByPassword(password)
	if err != nil {
		panic(err)
	}
	return c
}

func encryptOutside(buf []byte) []byte {
	currentCipher := outsideCipher
	ns := currentCipher.NonceSize()
	out := make([]byte, ns+len(buf)+currentCipher.Overhead())
	nonce := out[:ns]
	_, _ = rand.Read(nonce)
	ct := currentCipher.Seal(out[ns:ns], nonce, buf, nil)
	return out[:ns+len(ct)]
}

func decryptOutside(buf []byte) ([]byte, error) {
	currentCipher := outsideCipher
	ns := currentCipher.NonceSize()
	if len(buf) < ns {
		return nil, io.ErrUnexpectedEOF
	}
	return currentCipher.Open(buf[ns:ns], buf[:ns], buf[ns:], nil)
}

func configOutsideCipher(config *Config) error {
	var newCipher cipher.AEAD
	if keyEncoded := config.GetString("outside_encryption.key", ""); keyEncoded != "" {
		key, err := base64.StdEncoding.DecodeString(keyEncoded)
		if err != nil {
			return err
		}
		newCipher, err = chacha20poly1305.NewX(key)
		if err != nil {
			return err
		}
	} else {
		password := config.GetString("outside_encryption.password", defaultPassword)
		var err error
		newCipher, err = createChacha20CipherByPassword(password)
		if err != nil {
			return err
		}
	}
	outsideCipher = newCipher
	return nil
}
