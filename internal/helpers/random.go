package helpers

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

const (
	// The number of bytes we require to store a 64-bit value
	BytesFor64Bit = 64 / 8
)

// Returns a true-random hex string of a given length
func RandomHex(length int) string {
	randomBytes := make([]byte, (length+1)/2)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Errorf("RandomBase32 failed to read %d random bytes %w", (length+1)/2, err))
	}
	return hex.EncodeToString(randomBytes)[:length]
}

// Returns a true-random uint64 number
func RandomUint64() uint64 {
	var b [BytesFor64Bit]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Errorf("RandomUint64 failed to read %d random bytes %w", BytesFor64Bit, err))
	}
	return binary.LittleEndian.Uint64(b[:])
}
