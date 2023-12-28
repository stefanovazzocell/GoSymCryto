package helpers

import (
	"encoding/binary"
	"io"
)

// Writes a block of data of into a writer in such a way
// that we can later extract the same data
func Encode(writer io.Writer, data []byte) (err error) {
	// Write the data length to a bytes buffer
	buffer := binary.BigEndian.AppendUint64(nil, uint64(len(data)))
	// Write the buffer to the writer
	if _, err = writer.Write(buffer); err != nil {
		return
	}
	// Now write the data
	_, err = writer.Write(data)
	return
}

// Reads and returns a block of data from a reader in such
// a way that it matches the data from a encoder
func Decode(reader io.Reader) (data []byte, err error) {
	// Read the length of the next data block
	buffer := make([]byte, BytesFor64Bit)
	if _, err = io.ReadFull(reader, buffer); err != nil {
		return
	}
	length := binary.BigEndian.Uint64(buffer)
	// Read the data (given the length we decoded)
	data = make([]byte, length)
	_, err = io.ReadFull(reader, data)
	return
}
