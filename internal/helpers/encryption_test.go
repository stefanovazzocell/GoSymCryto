package helpers_test

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
)

var (
	// A slice of sample keys to use
	sampleKeys = [][helpers.KeySize]byte{
		{},
		hexToKey("6368616e676520746869732070617373776f726420746f206120736563726574"),
		hexToKey("9CC1EE455A3363FFC504F40006F70D0C8276648A5D3EB3F9524E94D1B7A83AEF"),
	}
	// Sample key A
	sampleKey = sampleKeys[1]
	// Test cases for the helpers.DeriveKey function
	deriveKeyTestCases = []struct {
		key           string
		derivedKeyHex string
	}{
		{key: "", derivedKeyHex: "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"},
		{key: "hello world", derivedKeyHex: "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"},
		{key: "gopher", derivedKeyHex: "9CC1EE455A3363FFC504F40006F70D0C8276648A5D3EB3F9524E94D1B7A83AEF"},
	}
	// Test cases for the helpers.Encrypt function
	encryptionTestCases = []struct {
		key       [helpers.KeySize]byte
		plaintext []byte
		hasErr    bool
	}{
		{
			key:       sampleKey,
			plaintext: []byte(""),
		},
		{
			key:       hexToKey("9CC1EE455A3363FFC504F40006F70D0C8276648A5D3EB3F9524E94D1B7A83AEF"),
			plaintext: []byte(""),
		},
		{
			key:       hexToKey("B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9"),
			plaintext: []byte("hello world"),
		},
		{
			key:       hexToKey("9CC1EE455A3363FFC504F40006F70D0C8276648A5D3EB3F9524E94D1B7A83AEF"),
			plaintext: []byte("gopher"),
		},
	}
	// Test cases for the helpers.Decrypt function
	decryptionTestCases = []struct {
		key        [helpers.KeySize]byte
		nonce      []byte
		ciphertext []byte
		plaintext  []byte
		hasErr     bool
	}{
		{
			key:        sampleKey,
			nonce:      hexDecode("64a9433eae7ccceee2fc0eda"),
			ciphertext: hexDecode("c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471"),
			plaintext:  []byte("exampleplaintext"),
		},
		{
			key:        sampleKey,
			nonce:      hexDecode("04a9433eae7ccceee2fc0eda"), // Altered
			ciphertext: hexDecode("c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471"),
			plaintext:  []byte("exampleplaintext"),
			hasErr:     true,
		},
		{
			key:        hexToKey("0368616e676520746869732070617373776f726420746f206120736563726574"), // Altered
			nonce:      hexDecode("64a9433eae7ccceee2fc0eda"),
			ciphertext: hexDecode("c3aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471"),
			plaintext:  []byte("exampleplaintext"),
			hasErr:     true,
		},
		{
			key:        sampleKey,
			nonce:      hexDecode("64a9433eae7ccceee2fc0eda"),
			ciphertext: hexDecode("03aaa29f002ca75870806e44086700f62ce4d43e902b3888e23ceff797a7a471"), // Altered
			plaintext:  []byte("exampleplaintext"),
			hasErr:     true,
		},
	}
)

func TestEncrypt(t *testing.T) {
	t.Parallel() // Can run in parallel
	for _, testCase := range encryptionTestCases {
		// Encrypt
		ciphertext, err := helpers.Encrypt(testCase.key, testCase.plaintext)
		if err != nil {
			t.Fatalf("got error encrypting %q with key %x: %v", testCase.plaintext, testCase.key, err)
		}

		// Decrypt encrypted data
		plaintext, err := helpers.Decrypt(testCase.key, ciphertext)
		if err != nil {
			t.Fatalf("got error decrypting %x (from %q) with key %x: %v", ciphertext, testCase.plaintext, testCase.key, err)
		}

		// Check if plaintext matches
		if !slices.Equal(plaintext, []byte(testCase.plaintext)) {
			t.Fatalf("the actual decrypted plaintext %q doesn't match %q (key %x)", plaintext, testCase.plaintext, testCase.key)
		}

		// Bonus: ciphertext should not contain plaintext
		// only if plaintext is longer than 1 byte
		if len(testCase.plaintext) > 1 && strings.Contains(string(ciphertext), string(testCase.plaintext)) {
			t.Fatalf("the ciphertext %q contains the plaintext %q", ciphertext, testCase.plaintext)
		}
	}
}

func TestDecrypt(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Special test: the ciphertext does not contain the nonce (len too short)
	if _, err := helpers.Decrypt([32]byte(sampleKey), make([]byte, helpers.NonceSize-1)); err != helpers.ErrInvalidCiphertextSize {
		t.Fatalf("expected ErrInvalidCiphertextSize when ciphertext is too short, instead got %v", err)
	}
	// Base test cases
	for i, testCase := range decryptionTestCases {
		// Check the key and nonce length
		if l := len(testCase.nonce); l != helpers.NonceSize {
			t.Fatalf("the nonce %x is of length %d but expected length %d", testCase.nonce, l, helpers.NonceSize)
		}
		// ciphertext should start with the nonce for our function
		ciphertext := append(testCase.nonce, testCase.ciphertext...)

		// Attempt decryption
		plaintext, err := helpers.Decrypt(testCase.key, ciphertext)
		if !testCase.hasErr && err != nil {
			t.Fatalf("got unexpected error decrypting %d: %v", i, err)
		}
		if testCase.hasErr && err == nil {
			t.Fatalf("expected error decrypting %d, instead got %q", i, plaintext)
		}
		if err == nil && !slices.Equal(plaintext, testCase.plaintext) {
			t.Fatalf("expected %d to decode to %q, instead got %q", i, testCase.plaintext, plaintext)
		}
	}
}

func FuzzEncryption(f *testing.F) {
	for _, testCase := range encryptionTestCases {
		f.Add([]byte(testCase.plaintext), testCase.key[:])
	}

	f.Fuzz(func(t *testing.T, plaintext []byte, key []byte) {
		// Verify key size
		if len(key) != helpers.KeySize {
			t.SkipNow()
		}

		// We have 3 goals here:
		// 1. Don't panic
		// 2. Don't error
		// 3. plaintext is equal to Decrypt(Encrypt(plaintext))

		// Encrypt
		ciphertext, err := helpers.Encrypt([32]byte(key), plaintext)
		if err != nil {
			t.Fatalf("got error encrypting %q with key %x: %v", plaintext, key, err)
		}

		// Decrypt encrypted data
		plaintextActual, err := helpers.Decrypt([32]byte(key), ciphertext)
		if err != nil {
			t.Fatalf("got error decrypting %x (from %q) with key %x: %v", ciphertext, plaintext, key, err)
		}

		// Check if plaintext matches
		if !slices.Equal(plaintextActual, []byte(plaintext)) {
			t.Fatalf("the actual decrypted plaintext %q doesn't match %q (key %x)", plaintextActual, plaintext, key)
		}
	})
}

// Returns a decoded hex string, panics on error
func hexDecode(data string) []byte {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		panic(err)
	}
	return decoded
}

// Decodes an hex string into a key.
//
// Panics if the hex string is the wrong size.
func hexToKey(key string) [helpers.KeySize]byte {
	data := hexDecode(key)
	if len(data) != helpers.KeySize {
		panic(fmt.Sprintf("hexToKey: %q is not the right key size (%d)", key, helpers.KeySize))
	}
	return [helpers.KeySize]byte(data)
}
