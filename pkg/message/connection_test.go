package message_test

import (
	"bytes"
	"errors"
	"log"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
	"github.com/stefanovazzocell/GoSymCryto/pkg/message"
)

func TestConnectionPingPong(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Setup server
	key := helpers.DeriveKey("")
	listener, err := testServer(nil, key)
	if err != nil {
		t.Fatalf("failed to setup server: %v", err)
	}
	defer func() {
		_ = listener.Close()
		if err = os.Remove(listener.Addr().String()); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to clean up listner at %q", listener.Addr().String())
		}
	}()
	// Ping-Pong
	testCases := [][]byte{
		[]byte(""),
		[]byte("ping"),
		[]byte("hello gopher"),
		make([]byte, 1000),
	}
	for _, data := range testCases {
		clientBackForth(listener, key, data, t)
	}
}

func TestConnectionComplex(t *testing.T) {
	t.Parallel() // Can run in parallel
	// Setup server
	key := helpers.DeriveKey("")
	listener, err := testServer(nil, key)
	if err != nil {
		t.Fatalf("failed to setup server: %v", err)
	}
	defer func() {
		_ = listener.Close()
		if err = os.Remove(listener.Addr().String()); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed to clean up listner at %q", listener.Addr().String())
		}
	}()
	// Complex
	conn, err := net.Dial(listener.Addr().Network(), listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect to the server: %v", err)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	connection, err := message.NewConnection(conn, key)
	if err != nil {
		connection.Close() // We still want to close the underlying connection
		t.Fatalf("failed to handshake: %v", err)
	}
	defer connection.Close()
	data := []byte("hello")
	if err = connection.WriteMessage(data); err != nil {
		t.Fatalf("failed to write 'hello' to server: %v", err)
	}
	message, err := connection.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read first message from server: %v", err)
	}
	if !bytes.Equal(message, data) {
		t.Fatalf("replied with unexpected message: %x (%q)", message, message)
	}
	data = []byte("world")
	if err = connection.WriteMessage(data); err != nil {
		t.Fatalf("failed to write 'world' to server: %v", err)
	}
	message, err = connection.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read second message from server: %v", err)
	}
	if !bytes.Equal(message, data) {
		t.Fatalf("replied with unexpected message: %x (%q)", message, message)
	}
}

// Useful utility to do a back-and-forth with the server as a client
func clientBackForth(listener net.Listener, key [helpers.KeySize]byte, data []byte, t *testing.T) {
	conn, err := net.Dial(listener.Addr().Network(), listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect to the server: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	connection, err := message.NewConnection(conn, key)
	if err != nil {
		t.Fatalf("failed to handshake: %v", err)
	}
	if err = connection.WriteMessage(data); err != nil {
		t.Fatalf("failed to write 'ping' to server: %v", err)
	}
	message, err := connection.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read message from server: %v", err)
	}
	if !bytes.Equal(message, data) {
		t.Fatalf("replied to ping with unexpected message: %x (%q)", message, message)
	}
}

// Creates a test server over a unix socket.
//
// if reply is nil, will parrot back whatever the user sends
func testServer(reply []byte, key [helpers.KeySize]byte) (listener net.Listener, err error) {
	// Come up with a random file
	currDir, err := os.Getwd()
	if err != nil {
		return
	}
	unixPath := path.Join(currDir, helpers.RandomHex(20)+".tmp")
	// Try to clear the socket path
	if err = os.Remove(unixPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
	// Setup listener
	listener, err = net.Listen("unix", unixPath)
	if err != nil {
		return
	}
	// Listen forever
	go func() {
		for {
			// Accept connection
			conn, err := listener.Accept()
			log.Printf("[server] accept (err=%v)", err)
			if errors.Is(err, net.ErrClosed) {
				log.Printf("[server] closed")
				continue // We're done here
			}
			if err != nil {
				continue // Whoops
			}
			// Initialize connection
			connection, err := message.NewConnection(conn, key)
			log.Printf("[server] connection (err=%v)", err)
			if err != nil {
				continue // Whoops
			}
			// Read, Write, Read, Write, Read, ...
			for {
				// Read a message
				message, err := connection.ReadMessage()
				log.Printf("[server] received message (%x, %v)", message, err)
				if err != nil {
					break // Whoops
				}
				// Write a message
				toSend := reply
				if reply == nil {
					toSend = message
				}
				err = connection.WriteMessage(toSend)
				log.Printf("[server] wrote message (err=%v)", err)
				if err != nil {
					break
				}
			}
		}
	}()

	// Return listener
	return
}
