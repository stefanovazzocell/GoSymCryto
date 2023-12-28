package crypto

import "github.com/stefanovazzocell/GoSymCryto/internal/helpers"

// Encrypt a message using the provided key.
func Encrypt(key AESKey, plaintext []byte) (ciphertext []byte, err error) {
	return helpers.Encrypt(key, plaintext)
}

// Decrypts a message (prefixed by a salt value) using the provided key.
func Decrypt(key AESKey, ciphertext []byte) (plaintext []byte, err error) {
	return helpers.Decrypt(key, ciphertext)
}
