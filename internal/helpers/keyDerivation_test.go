package helpers_test

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"runtime"
	"slices"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
	"golang.org/x/crypto/argon2"
)

const ()

var (
	// Min value for time (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMinTime uint32 = 1
	// Max value for time (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMaxTime uint32 = 3
	// Min value for memory (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMinMemory uint32 = 1
	// Max value for memory (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMaxMemory uint32 = 128 * 1024
	// Min value for paralelism (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMinParallelism uint8 = 1
	// Max value for paralelism (used by the fuzzer for DeriveKeySecure)
	FuzzDeriveKeySecureMaxParallelism uint8 = uint8(min(runtime.NumCPU()*2, math.MaxUint8))
	// Test cases to verify argon2id hashing.
	//
	// Generated from the `argon2` package for Fedora.
	argon2idTestCases = []struct {
		password    string
		salt        []byte
		time        uint32
		memory      uint32
		parallelism uint8
		derivedKey  [helpers.KeySize]byte
	}{
		// `echo -n "somepassword" | argon2 "somesalt" -id -t 3 -k 4096 -p 1 -l 32 -r -v 13`
		{"somepassword", []byte("somesalt"), 3, 4096, 1, hexToKey("e802d7f1de82db6df4a05d0c72d09e79d599ed3776fe538bf9ddf6cc5e890925")},
		// `echo -n "my super secure password" | argon2 "I'm salty!" -id -t 2 -k 126976 -p 8 -l 32 -r -v 13`
		{"my super secure password", []byte("I'm salty!"), 2, 126976, 8, hexToKey("10e7829e8c22ef038a02644eaca0372ba8bce48b5fd44ad67ec30501fbe1071a")},
		// `echo -n "?" | argon2 "I'm salty!" -id -t 2 -k 126976 -p 8 -l 32 -r -v 13`
		{"?", []byte("I'm salty!"), 2, 126976, 8, hexToKey("dac975433ec06b73c9c196e6d866db4d707578112904c0b9d4d8004542836076")},
	}
)

func TestDeriveKey(t *testing.T) {
	t.Parallel() // Can run in parallel
	for _, testCase := range deriveKeyTestCases {
		expectedDerivedKey, err := hex.DecodeString(testCase.derivedKeyHex)
		if err != nil {
			t.Fatalf("failed to decode expected derived key: %v", err)
		}
		if l := len(expectedDerivedKey); l != 32 {
			t.Fatalf("incorrect length of expected derived key: expected 32 byte but got %d", l)
		}

		derivedKeyActual := helpers.DeriveKey(testCase.key)
		derivedKeyAlt := deriveKeyAlt(testCase.key)

		if derivedKeyActual != derivedKeyAlt {
			t.Errorf("derived key for %q doesn't match between actual (%x) and alt (%x)", testCase.key, derivedKeyActual, derivedKeyAlt)
		}
		if !slices.Equal(derivedKeyActual[:], expectedDerivedKey) {
			t.Errorf("derived key for %q doesn't match between actual (%x) and expected (%x)", testCase.key, derivedKeyActual, expectedDerivedKey)
		}
	}
}

func TestDeriveSecureKey(t *testing.T) {
	t.Parallel() // Can run in parallel
	for _, testCase := range argon2idTestCases {
		derivedKey := helpers.DeriveKeySecure(testCase.password, testCase.salt, testCase.time, testCase.memory, testCase.parallelism)

		expected := hex.EncodeToString(testCase.derivedKey[:])
		actual := hex.EncodeToString(derivedKey[:])
		if expected != actual {
			t.Logf("`echo -n %q | argon2 %q -id -t %d -k %d -p %d -l 32 -r -v 13` = %q", testCase.password, testCase.salt, testCase.time, testCase.memory, testCase.parallelism, expected)
			t.Logf(`helpers.DeriveKeySecure(%q, %q, %d, %d, %d) = %q`, testCase.password, testCase.salt, testCase.time, testCase.memory, testCase.parallelism, actual)
			t.Fatalf("Test case for %q failed; see above.", testCase.password)
		}
	}
}

func FuzzDeriveKey(f *testing.F) {
	for _, testCase := range deriveKeyTestCases {
		f.Add(testCase.key)
	}

	f.Fuzz(func(t *testing.T, key string) {
		// We have 2 goals here:
		// 1. Don't panic
		// 2. Produce a key that matches that from deriveKeyAlt

		derivedActual := helpers.DeriveKey(key)
		derivedAlt := deriveKeyAlt(key)

		if derivedActual != derivedAlt {
			t.Fatalf("the derived key (%x) doesn't match the alt derived key (%x)", derivedActual, derivedAlt)
		}
	})
}

func FuzzDeriveSecureKey(f *testing.F) {
	for _, testCase := range argon2idTestCases {
		f.Add(testCase.password, testCase.salt, testCase.time, testCase.memory, testCase.parallelism)
	}

	f.Fuzz(func(t *testing.T, password string, salt []byte, time uint32, memory uint32, parallelism uint8) {
		// We have 2 goals here:
		// 1. Don't panic
		// 2. Produce a key that matches that from deriveKeyAlt

		// Check if we're outside of the allowed boundaries
		if time < FuzzDeriveKeySecureMinTime || FuzzDeriveKeySecureMaxTime < time {
			t.SkipNow()
		}
		if memory < FuzzDeriveKeySecureMinMemory || FuzzDeriveKeySecureMaxMemory < memory {
			t.SkipNow()
		}
		if parallelism < FuzzDeriveKeySecureMinParallelism || FuzzDeriveKeySecureMaxParallelism < parallelism {
			t.SkipNow()
		}

		derivedActual := helpers.DeriveKeySecure(password, salt, time, memory, parallelism)
		derivedAlt := deriveSecureKeyAlt(password, salt, time, memory, parallelism)

		if derivedActual != derivedAlt {
			t.Fatalf("the derived key (%x) doesn't match the alt derived key (%x)", derivedActual, derivedAlt)
		}
	})
}

// An altearnative implementation of helpers.DeriveKey
func deriveKeyAlt(password string) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(password))
	result := [32]byte{}
	copy(result[:], hash.Sum(nil))
	return result
}

// An altearnative implementation of helpers.DeriveKeySecure
func deriveSecureKeyAlt(password string, salt []byte, time uint32, memory uint32, parallelism uint8) [32]byte {
	result := [32]byte{}
	copy(result[:], argon2.IDKey([]byte(password), salt, time, memory, parallelism, helpers.KeySize))
	return result
}
