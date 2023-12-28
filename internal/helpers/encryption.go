package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// The nonce size.
	// note: the GCM specification recomands a 12-byte nonce
	NonceSize = 12
	// The key size.
	// note: using 32-byte for AES-GCM-256
	KeySize = 32
)

var (
	// Error returned when the ciphertext given to the decryption function is less
	// than the lenght of the nonce (which it is supposed to start with).
	ErrInvalidCiphertextSize = errors.New("invalid ciphertext size: it is not long enough to contain the nonce")
)

// Encrypt some plaintext data with a key
func Encrypt(key [KeySize]byte, plaintext []byte) (ciphertext []byte, err error) {
	// Create cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // The key must be the right size (unless we got a wrong KeySize)
	}

	// Create a true random nonce
	nonce := make([]byte, NonceSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return
	}

	// Setup the AEAD cipher (AES GCM)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err) // As long as we use a standard NonceSize we should never hit this error
	}

	// Encrypt data
	ciphertext = aesgcm.Seal(nonce, nonce, plaintext, nil)

	return
}

// Decrypt some plaintext data with a key
func Decrypt(key [KeySize]byte, ciphertext []byte) (plaintext []byte, err error) {
	// Check the length of the ciphertext
	if len(ciphertext) < NonceSize {
		err = ErrInvalidCiphertextSize
		return
	}

	// Create cipher block
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // The key must be the right size (unless we got a wrong KeySize)
	}

	// Get the 16-bit nonce
	nonce := ciphertext[0:NonceSize]
	ciphertext = ciphertext[NonceSize:]

	// Setup the AEAD cipher (AES GCM)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err) // As long as we use a standard NonceSize we should never hit this error
	}

	// Decrypt data
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)

	return
}
