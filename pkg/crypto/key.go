package crypto

import "github.com/stefanovazzocell/GoSymCryto/internal/helpers"

const (
	// Default time value for `DeriveSecureKey` to use with Argon2id
	DefaultTime uint32 = 2
	// Default memory value for `DeriveSecureKey` to use with Argon2id
	DefaultMemory uint32 = 124 * 1024 // 124 MiB
	// Default threads value for `DeriveSecureKey` to use with Argon2id
	DefaultParallelism uint8 = 4 * 2 // Assuming most processors have >=4 cores
)

var (
	// Salt used in case `DeriveKeySecure` is called with `nil` as salt.
	DefaultSalt = []byte{163, 90, 143, 1, 169, 73, 126, 71, 149, 0, 49, 114, 247, 182, 221, 229, 185, 37, 74, 69, 68, 112, 44, 66, 109, 233, 126, 29, 169, 95, 40, 59, 235, 179, 92, 137, 179, 178, 117, 209, 42, 107, 106, 179, 2, 169, 144, 37, 239, 230, 186, 31, 90, 65, 5, 126, 186, 192, 215, 23, 175, 45, 150, 47}
)

// A key to use for AES encryption/decryption
type AESKey [helpers.KeySize]byte

// Derives a key from a string using SHA256.
//
// NOTE: Only use this function if your password is known
// to be secure (long, unique, ...); otherwise use the
// `DeriveSecureKey` function.
func DeriveKey(password string) AESKey {
	return helpers.DeriveKey(password)
}

// Securely derives a key from a string and some salt
// using PBKDF2 and SHA256.
//
// If salt is `nil`, a default value will be used.
// Ideally you should generate your own unique salt value
// with the provided tools.
//
// For any of time, memory, and threads equal to `0`, it will
// be replaced by a default secure value.
func DeriveSecureKey(password string, salt []byte, time uint32, memory uint32, threads uint8) AESKey {
	// Set default salt if provided value is nil
	if salt == nil {
		salt = DefaultSalt
	}
	// Set default time if not provided
	if time == 0 {
		time = DefaultTime
	}
	// Set default memory if not provided
	if memory == 0 {
		memory = DefaultMemory
	}
	// Set default threads if not provided
	if threads == 0 {
		threads = DefaultParallelism
	}
	return helpers.DeriveKeySecure(password, salt, time, memory, threads)
}
