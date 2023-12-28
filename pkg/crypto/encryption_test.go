package crypto_test

import (
	"fmt"

	"github.com/stefanovazzocell/GoSymCryto/pkg/crypto"
)

func ExampleEncrypt() {
	key := crypto.DeriveSecureKey("secret password", nil, 0, 0, 0)
	ciphertext, err := crypto.Encrypt(key, []byte("hi gopher"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("ciphertext = %x", ciphertext)
}

func ExampleDecrypt() {
	key := crypto.DeriveSecureKey("secret password", nil, 0, 0, 0)
	ciphertext, err := crypto.Encrypt(key, []byte("hello world"))
	if err != nil {
		panic(err)
	}
	plaintext, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		panic(err)
	}
	fmt.Printf("plaintext = %q", plaintext)
	// Output: plaintext = "hello world"
}
