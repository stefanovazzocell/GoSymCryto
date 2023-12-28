package message

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/stefanovazzocell/GoSymCryto/internal/helpers"
	"github.com/stefanovazzocell/GoSymCryto/pkg/crypto"
)

var (
	// Error returned when the remote message is too small to
	// contain a challenge
	ErrInvalidRemoteMessageSize = errors.New("remote message is too small to contain a challenge")
	// Error returned when the remote message has the wrong
	// value for the challenge
	ErrInvalidRemoteMessageChallenge = errors.New("remote message provided the wrong challenge")
)

// Connection can manage a connection and other factors such as
// cryptography and security, providing a simple interface to
// read and write data
type Connection struct {
	// The underlying connection
	conn net.Conn
	// The encryption key
	key crypto.AESKey
	// A lock for the sender
	writeLock *sync.Mutex
	// The remote challenge value
	challengeRemote uint64
	// A counter tracking the number of messages received
	counterRemote uint64
	// A lock for the receiver
	readLock *sync.Mutex
	// The local challenge value
	challengeLocal uint64
	// A counter tracking the number of messages sent
	counterLocal uint64
}

// Performs a handshake and returns a Connection object or an error otherwise
func NewConnection(conn net.Conn, key crypto.AESKey) (connection *Connection, err error) {
	connection = &Connection{
		conn:      conn,
		writeLock: &sync.Mutex{},
		readLock:  &sync.Mutex{},
	}
	// Perform handshake
	err = connection.handshake()
	return
}

// Closes the underlying connection
func (conn *Connection) Close() (err error) {
	return conn.conn.Close()
}

// Writes a message to the remote connection
func (conn *Connection) WriteMessage(data []byte) (err error) {
	conn.writeLock.Lock()
	defer conn.writeLock.Unlock()
	// Generate the next sequence number
	sequenceNumber := conn.nextOutgoingSequenceNumber()
	// AppendChallenge > Encrypt > PrefixWithLength > Write
	return helpers.WriteEncryptedMessage(conn.conn, conn.key, sequenceNumber, data)
}

// Reads a block of data from the connection
func (conn *Connection) ReadMessage() (data []byte, err error) {
	conn.readLock.Lock()
	defer conn.readLock.Unlock()
	// Generate the next expected sequence number
	sequenceNumber := conn.nextExpectedIncomingSequenceNumber()
	// Read > ExtractLength > Decrypt > VerifyChallenge
	return helpers.ReadEncryptedMessage(conn.conn, conn.key, sequenceNumber)
}

// Performs a challenge-response handshake
func (conn *Connection) handshake() (err error) {
	// To prevent replay-attacks we perform a handshake where the
	// two peers exchange a challenge.
	//
	// The handshake (from the local prospective) goes as such:
	// 1. we generate a challenge and send it to the *remote* peer
	// 2. we receive the *remote* challenge
	//
	// For each message sent, we'll prefix the data with
	// `((challengeLocal * counterLocal) ^ challengeRemote)`
	// and we will increment `counterLocal`.
	//
	// For each message received we'll read the prefix and expect it
	// to match `(challengeLocal ^ (challengeRemote * counterRemote))`
	// and increment `counterRemote`.
	//
	// If the remote message prefix does not match our expected value
	// we can close the connection and return an error.

	// Initialize the counters
	conn.counterLocal = 0
	conn.counterRemote = 0
	// Initialize the local challenge
	conn.challengeLocal = helpers.RandomUint64()

	// Exchange the challenges (send local)
	localChallengeBytes := binary.BigEndian.AppendUint64(nil, conn.challengeLocal)
	err = helpers.WriteEncrypted(conn.conn, conn.key, localChallengeBytes)
	if err != nil {
		return
	}

	// Exchange the challenges (receive remote)
	remoteChallengeBytes, err := helpers.ReadEncrypted(conn.conn, conn.key)
	if err != nil {
		return
	}
	conn.challengeRemote = binary.BigEndian.Uint64(remoteChallengeBytes)
	return
}

// Returns the sequence number to be appended to the next outgoing message
func (conn *Connection) nextOutgoingSequenceNumber() (sequenceNumber uint64) {
	// Please see the comment in handshake() for an understanding
	// on how the challange works.
	//
	// The idea here is just to add the challenge to the data we'll send
	// to the remote peer. The remote will be responsible to verify it.

	// Calculate the next sequence number
	sequenceNumber = (conn.challengeLocal * conn.counterLocal) ^ conn.challengeRemote

	// Increment the local counter
	conn.counterLocal++
	return
}

// Returns the sequence number that we expect to see on the next received message
func (conn *Connection) nextExpectedIncomingSequenceNumber() (sequenceNumber uint64) {
	// Please see the comment in handshake() for an understanding
	// on how the challange works.
	//
	// The idea is to verify that the received data has a valid and
	// correct challenge. Also filter the challenge out of the data

	// Verify that the remote challenge has the expected value
	sequenceNumber = conn.challengeLocal ^ (conn.challengeRemote * conn.counterRemote)

	// Increment the remote counter
	conn.counterRemote++
	return
}
