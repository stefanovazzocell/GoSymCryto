package helpers_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
)

const (
	// We will test RandomHex to check if it generates the correct
	// hex length up to a length of UPPER_HEX_LENGTH
	UPPER_RANDOMHEX_LENGTH int = 10000
	// The number of runs of randomhex that we execute to test the parallelism
	PARALLEL_RANDOMHEX_TESTS int = 10000
	// Number of random uint64 to check for conflict
	RANDOM_UINT64_REPEATING int = 100000
	// The number of runs of randomuint64 that we execute to test the parallelism
	PARALLEL_RANDOMUINT64_TESTS int = 100000
)

func TestRandomHex(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Test that it gives the right length (from 0 to UPPER_HEX_LENGTH)
	for i := 0; i <= UPPER_RANDOMHEX_LENGTH; i++ {
		hex := helpers.RandomHex(i)
		if len(hex) != i {
			t.Fatalf("helpers.RandomHex(%d) returned %q of length %d", i, hex, len(hex))
		}
	}
}

func TestRandomUint64(t *testing.T) {
	// NOTE: this function might at times detect random conflicts but it should be
	//       an extremely rare occurance
	t.Parallel() // Can run in parallel
	// Check for repeating numbers
	seen := make(map[uint64]bool, RANDOM_UINT64_REPEATING)
	for i := 0; i < RANDOM_UINT64_REPEATING; i++ {
		newUint64 := helpers.RandomUint64()
		if seen[newUint64] {
			t.Fatalf("Found a conflict with %d at the %d try", newUint64, i+1)
		}
		seen[newUint64] = true
	}
}

func TestRandomUint64Parallelism(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Test parallel generation (check for crashes)
	runs := runtime.NumCPU() * 2
	errChan := make(chan error, runs)
	for i := 0; i < runs; i++ {
		go func() {
			for i := 0; i < PARALLEL_RANDOMUINT64_TESTS; i++ {
				_ = helpers.RandomUint64()
			}
			errChan <- nil
		}()
	}
	for i := 0; i < runs; i++ {
		if err := <-errChan; err != nil {
			t.Error(err)
		}
	}
}

func TestRandomHexParallelism(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Test parallel generation (check for crashes)
	runs := runtime.NumCPU() * 2
	errChan := make(chan error, runs)
	for i := 0; i < runs; i++ {
		go func() {
			hex := ""
			for i := 0; i < PARALLEL_RANDOMHEX_TESTS; i++ {
				if hex = helpers.RandomHex(i); len(hex) != i {
					errChan <- fmt.Errorf("helpers.RandomHex(%d) returned %q of length %d", i, hex, len(hex))
					return
				}
			}
			errChan <- nil
		}()
	}
	for i := 0; i < runs; i++ {
		if err := <-errChan; err != nil {
			t.Error(err)
		}
	}
}
