package helpers_test

import (
	"bytes"
	"math"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
)

var (
	// A list of sample messages to use for testing
	sampleMessages = [][]byte{
		{}, // Empty
		{0},
		{1},
		{255},
		[]byte("hello world"),
		[]byte("{\"user\":\"bob\",\"action\":\"ping\"}"),
		make([]byte, 2^10), // 1 KB
		make([]byte, 2^20), // 1 MB
		make([]byte, 2^30), // 1 GB
	}
	// A list of sample sequenceNumbers to use for testing
	sampleSequenceNumbers = []uint64{
		0,
		1,
		2,
		3,
		2 ^ 10,
		2 ^ 20,
		2 ^ 30,
		math.MaxUint64,
	}
)

func TestWriteReadEncrypted(t *testing.T) {
	t.Parallel() // Can run in parallel
	for _, key := range sampleKeys {
		for _, message := range sampleMessages {
			// Log which key+message pair we're using
			if len(message) > 16 {
				t.Logf("> using message '%x' (len %d)... with key %x", message[:16], len(message), key)
			} else {
				t.Logf("> using message '%x' with key %x", message, key)
			}
			// Setup buffer
			buffer := bytes.NewBuffer([]byte{})
			// Encrypt the message
			err := helpers.WriteEncrypted(buffer, key, message)
			if err != nil {
				t.Fatalf("got error while encrypting message: %x", err)
			}
			// Verify that we don't obviously leak any data
			unread := buffer.Bytes()
			if bytes.Contains(unread, key[:]) {
				t.Fatalf("the encrypted data contains the key we used")
			}
			if len(message) > 1 && bytes.Contains(unread, message) {
				t.Fatalf("the encrypted data contains the message we used")
			}
			// Decrypt the message
			decrypted, err := helpers.ReadEncrypted(buffer, key)
			if err != nil {
				t.Fatalf("got error while decrypting message: %x", err)
			}
			if !bytes.Equal(decrypted, message) {
				if len(decrypted) > 16 {
					t.Fatalf("decrypted message %x (len %d)... doesn't match original", decrypted[:16], len(decrypted))
				} else {
					t.Fatalf("decrypted message %x... doesn't match original", decrypted)
				}
			}
			// Check if the buffer has data
			if buffer.Len() > 0 {
				t.Fatalf("the buffer still has %d unread bytes", buffer.Len())
			}
		}
	}
}

func TestWriteReadEncryptedMessage(t *testing.T) {
	t.Parallel() // Can run in parallel
	for _, sequenceNumber := range sampleSequenceNumbers {
		for _, key := range sampleKeys {
			for _, message := range sampleMessages {
				// Log which key+message pair we're using
				if len(message) > 16 {
					t.Logf("> using message '%x' (len %d)... with key %x and seq # %d", message[:16], len(message), key, sequenceNumber)
				} else {
					t.Logf("> using message '%x' with key %x and seq # %d", message, key, sequenceNumber)
				}
				// Setup buffer
				buffer := bytes.NewBuffer([]byte{})
				// Encrypt the message
				err := helpers.WriteEncryptedMessage(buffer, key, sequenceNumber, message)
				if err != nil {
					t.Fatalf("got error while encrypting message: %x", err)
				}
				// Verify that we don't obviously leak any data
				unread := buffer.Bytes()
				if bytes.Contains(unread, key[:]) {
					t.Fatalf("the encrypted data contains the key we used")
				}
				if len(message) > 1 && bytes.Contains(unread, message) {
					t.Fatalf("the encrypted data contains the message we used")
				}
				// Decrypt the message
				decrypted, err := helpers.ReadEncryptedMessage(buffer, key, sequenceNumber)
				if err != nil {
					t.Fatalf("got error while decrypting message: %x", err)
				}
				if !bytes.Equal(decrypted, message) {
					if len(decrypted) > 16 {
						t.Fatalf("decrypted message %x (len %d)... doesn't match original", decrypted[:16], len(decrypted))
					} else {
						t.Fatalf("decrypted message %x... doesn't match original", decrypted)
					}
				}
				// Replay Attack
				incorrectSequenceNumber := sequenceNumber + 1
				if _, err := buffer.Write(unread); err != nil {
					t.Fatalf("failed to replay the encrypted message: %v", err)
				}
				decrypted, err = helpers.ReadEncryptedMessage(buffer, key, incorrectSequenceNumber)
				if decrypted != nil || err != helpers.ErrInvalidRemoteMessageChallenge {
					t.Fatalf("failed replay attack check: expected invalid challenge err, instead got (len(data)=%d, %v)", len(decrypted), err)
				}
				// Check if the buffer has data
				if buffer.Len() > 0 {
					t.Fatalf("the buffer still has %d unread bytes", buffer.Len())
				}
			}
		}
	}
}
