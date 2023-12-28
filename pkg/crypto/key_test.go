package crypto_test

import (
	"fmt"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/pkg/crypto"
)

func ExampleDeriveKey() {
	key := crypto.DeriveKey("A complex secret secure password that only the two peers know")
	fmt.Printf("key = %x", key)
	// Output: key = 37abcb7a6139dba8ef60fc401aa580a2fb9d0afda53a2f699970aa63b3495896
}

func ExampleDeriveSecureKey() {
	key := crypto.DeriveSecureKey("A secret password", nil, 0, 0, 0)
	fmt.Printf("salt = %x\n", crypto.DefaultSalt)
	fmt.Printf("key = %x", key)
	// Output:
	// salt = a35a8f01a9497e4795003172f7b6dde5b9254a4544702c426de97e1da95f283bebb35c89b3b275d12a6b6ab302a99025efe6ba1f5a41057ebac0d717af2d962f
	// key = aad9f8f274967dd24cb7e483ad872744b79e0d1d3e5a6facc0c4bf855bb07d46
}

func TestDeriveSecureKey(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Here we just want to check that the program
	// doesn't crash when we pass nil for salt and
	// 0 for all uint* parameters (as they should
	// be replaced by some default values)
	password := "hello gopher"
	actualKey := crypto.DeriveSecureKey(password, nil, 0, 0, 0)
	expectedKey := crypto.DeriveSecureKey(password, crypto.DefaultSalt, crypto.DefaultTime, crypto.DefaultMemory, crypto.DefaultParallelism)
	if actualKey != expectedKey {
		t.Fatalf("Expected %x but got %x", expectedKey, actualKey)
	}
}

func BenchmarkDerive(b *testing.B) {
	b.Run("Key", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			crypto.DeriveKey("some password here")
		}
	})
	b.Run("SecureKey", func(b *testing.B) {
		// Using the default parameters
		for i := 0; i < b.N; i++ {
			_ = crypto.DeriveSecureKey("some password here", nil, 0, 0, 0)
		}
	})
}
