# GoSymCrypto

Go Symmetric Cryptography aims to provide some tools to encrypt/decrypt data using symmetric cryptography in a way that is safe by default.
This package contains two packages: a simpler `crypto` library and a more advanced `message` one.

## Crypto

The `crypto` package provides simpler utilities to encrypt and decrypt data. It provides utilities to derive a secure key and automatically
generates a secure random nonce.

### Example 

```go
key := crypto.DeriveSecureKey("secret password", nil, 0, 0, 0)
ciphertext, err := crypto.Encrypt(key, []byte("hello world"))
if err != nil {
	panic(err)
}
plaintext, err := crypto.Decrypt(key, ciphertext)
if err != nil {
	panic(err)
}
```

## Message

The `message` package allows users to create use symmetric cryptography between two peers via a `net.Conn` interface.

This can be used to enable peer-to-peer communications using a symmetric key while making replay attacks more challenging to perform thanks
to a randomized challenge value that gets used during the communications.

### Example 

```go
// setup some `conn net.Conn`...
conn.SetDeadline(time.Now().Add(time.Second))
connection, err := message.NewConnection(conn, key)
if err != nil {
	connection.Close() // We still want to close the underlying connection
	panic(fmt.Sprintf("handshake failed: %v", err))
}
defer connection.Close()
data := []byte("hello")
if err = connection.WriteMessage([]byte("hello")); err != nil {
	panic(fmt.Sprintf("failed to write 'hello' to server: %v", err))
}
message, err := connection.ReadMessage()
if err != nil {
	panic(fmt.Sprintf("failed to read message from server: %v", err))
}
fmt.Sprintf("Reply: %q", message)
```
