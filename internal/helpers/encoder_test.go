package helpers_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
)

var (
	// Test cases for (helpers.)Encode/Decode
	encodingTestCases = []struct {
		data    []byte
		encoded []byte
	}{
		{data: []byte{}, encoded: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{data: []byte{1}, encoded: []byte{0, 0, 0, 0, 0, 0, 0, 1, 1}},
		{data: []byte{50, 42, 10}, encoded: []byte{0, 0, 0, 0, 0, 0, 0, 3, 50, 42, 10}},
		{data: make([]byte, 1000), encoded: append([]byte{0, 0, 0, 0, 0, 0, 0x3, 0xe8}, make([]byte, 1000)...)},
	}
	// Test cases for the encoding benchmarks
	encodingBenchmarksTestCases = []struct {
		name string
		size int
	}{
		{name: "64B", size: 2 ^ 6},
		{name: "1KB", size: 2 ^ 10},
		{name: "1MB", size: 2 ^ 20},
	}
)

func TestEncoding(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Test Encode/Decode
	for _, testCase := range encodingTestCases {
		encoded := encode(testCase.data)
		if !bytes.Equal(encoded, testCase.encoded) {
			t.Fatalf("failed to encode %x: got %x instead of %x", testCase.data, encoded, testCase.encoded)
		}
		decoded := decode(testCase.encoded)
		if !bytes.Equal(decoded, testCase.data) {
			t.Fatalf("failed to decode %x: got %x instead of %x", testCase.encoded, decoded, testCase.data)
		}
	}
	// Test Encode > Decode
	for _, testCase := range encodingTestCases {
		buffer := bytes.NewBuffer([]byte{})
		if err := helpers.Encode(buffer, testCase.data); err != nil {
			t.Fatalf("failed to encode %x: %v", testCase.data, err)
		}
		decoded, err := helpers.Decode(buffer)
		if err != nil {
			t.Fatalf("failed to decode data from %x: %v", testCase.data, err)
		}
		if !bytes.Equal(decoded, testCase.data) {
			t.Fatalf("there is a mismatch in the final result: expected %x, but decoded %x", testCase.data, decoded)
		}
	}
}

func BenchmarkEncode(b *testing.B) {
	for _, test := range encodingBenchmarksTestCases {
		data := make([]byte, test.size)
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				helpers.Encode(bytes.NewBuffer([]byte{}), data)
			}
		})
	}
}

func BenchmarkDecode(b *testing.B) {
	for _, test := range encodingBenchmarksTestCases {
		data := make([]byte, test.size)
		buffer := bytes.NewBuffer([]byte{})
		err := helpers.Encode(buffer, data)
		if err != nil {
			b.Fatalf("errored while encoding: %v", err)
		}
		encoded, err := io.ReadAll(buffer)
		if err != nil {
			b.Fatalf("errored while reading encoded data: %v", err)
		}
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				helpers.Decode(bytes.NewBuffer([]byte(encoded)))
			}
		})
	}
}

func FuzzEncoding(f *testing.F) {
	for _, testCase := range encodingTestCases {
		f.Add(testCase.data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		buffer := bytes.NewBuffer([]byte{})
		if err := helpers.Encode(buffer, data); err != nil {
			t.Fatalf("failed to encode %x: %v", data, err)
		}
		decoded, err := helpers.Decode(buffer)
		if err != nil {
			t.Fatalf("failed to decode data from %x: %v", data, err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatalf("there is a mismatch in the final result: expected %x, but decoded %x", data, decoded)
		}
	})
}

// Wrapper for helpers.Encode that returns []byte directly
func encode(data []byte) (encoded []byte) {
	buffer := bytes.NewBuffer([]byte{})
	if err := helpers.Encode(buffer, data); err != nil {
		panic(err)
	}
	encoded, err := io.ReadAll(buffer)
	if err != nil {
		panic(err)
	}
	return
}

// Wrapper for helpers.Decode that decodes []byte directly
func decode(encoded []byte) (data []byte) {
	buffer := bytes.NewBuffer(encoded)
	data, err := helpers.Decode(buffer)
	if err != nil {
		panic(err)
	}
	return
}
