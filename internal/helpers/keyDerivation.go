package helpers

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
)

// Derives a 32 byte key from a password using SHA256
func DeriveKey(password string) [KeySize]byte {
	return sha256.Sum256([]byte(password))
}

// Derives a 32 byte key from a password using Argon2id
func DeriveKeySecure(password string, salt []byte, time uint32, memory uint32, parallelism uint8) (derivedKey [KeySize]byte) {
	keyBytes := argon2.IDKey([]byte(password), salt, time, memory, parallelism, KeySize)
	if len(keyBytes) != KeySize {
		// argon2.Key promises us a key of the expected size, we check that promise here
		panic("derived key doesn't match expected key size")
	}
	copy(derivedKey[:], keyBytes[:KeySize])
	return
}
