package helpers

import (
	"encoding/binary"
	"errors"
	"io"
)

var (
	// Error returned when the remote message is too small to
	// contain a challenge
	ErrInvalidRemoteMessageSize = errors.New("remote message is too small to contain a challenge")
	// Error returned when the remote message has the wrong
	// value for the challenge
	ErrInvalidRemoteMessageChallenge = errors.New("remote message provided the wrong challenge")
)

// Encrypts, encodes and writes data to writer
func WriteEncrypted(writer io.Writer, key [KeySize]byte, data []byte) (err error) {
	ciphertext, err := Encrypt(key, data)
	if err != nil {
		data = nil
		return
	}
	return Encode(writer, ciphertext)
}

// Reads, decodes, and decrypts data
func ReadEncrypted(reader io.Reader, key [KeySize]byte) (data []byte, err error) {
	ciphertext, err := Decode(reader)
	if err != nil {
		data = nil
		return
	}
	return Decrypt(key, ciphertext)
}

// Encrypts, encodes and writes data to writer
//
// The provided sequenceNumber will be encoded with the data
func WriteEncryptedMessage(writer io.Writer, key [KeySize]byte, sequenceNumber uint64, data []byte) (err error) {
	// Encode and send the message
	return WriteEncrypted(writer, key, append(binary.BigEndian.AppendUint64(nil, sequenceNumber), data...))
}

// Reads, decodes, and decrypts data
//
// If the sequenceNumber received doesn't match the expected value or is not present, an error will be returned
func ReadEncryptedMessage(reader io.Reader, key [KeySize]byte, sequenceNumber uint64) (data []byte, err error) {
	// Read and decrypt message
	data, err = ReadEncrypted(reader, key)
	if err != nil {
		data = nil
		return
	}
	// Check sequence number
	if len(data) < BytesFor64Bit {
		data = nil
		err = ErrInvalidRemoteMessageSize
		return
	}
	if binary.BigEndian.Uint64(data[0:BytesFor64Bit]) != sequenceNumber {
		data = nil
		err = ErrInvalidRemoteMessageChallenge
		return
	}
	// Remove the sequence number from the data
	data = data[BytesFor64Bit:]
	return
}
