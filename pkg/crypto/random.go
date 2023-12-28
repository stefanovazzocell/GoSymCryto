package crypto

import (
	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
)

// Returns a true-random hex string of a given length
func RandomHex(length int) string {
	return helpers.RandomHex(length)
}

// Returns a true-random uint64 number
func RandomUint64() uint64 {
	return helpers.RandomUint64()
}
