package tunnel

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
)

type Key []byte

// KeyList key - md5 sum of public key
type MD5Key [md5.Size]byte

// KeyList is a list of public keys
// It allows to authenticate multiple public keys
type KeyList map[MD5Key]Key

// Creates a list of Public Keys
func NewKeyList(keys ...interface{}) KeyList {
	keylist := make(KeyList)
	for _, key := range keys {
		keylist.Add(key)
	}
	return keylist
}

// Adds Public Key to the list
func (l KeyList) Add(key interface{}) error {
	if key == nil {
		return fmt.Errorf("Key cannot be nil")
	}

	// Marshal the key
	keybytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	// Get MD5 checksum of key
	id := md5.Sum(keybytes)

	// Add a key to the map
	l[id] = Key(keybytes)

	return nil
}

// Checks if key exists on the list
func (l KeyList) Has(key interface{}) bool {
	if key == nil {
		return false
	}

	// Marshal the key
	keybytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil || len(keybytes) == 0 {
		return false
	}

	return l.HasBytes(keybytes)
}

// Checks if key exists on the list
func (l KeyList) HasBytes(keybytes []byte) bool {
	// Get MD5 checksum of key
	id := md5.Sum(keybytes)

	key := l[id]
	if key == nil {
		return false
	}

	return key.EqualBytes(keybytes)
}

// Verifies if client's certificate is listed in Server CertList
func (l KeyList) VerifyConn(conn net.Conn) (*tls.Conn, error) {
	tlsconn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("Package internal error: cannot convert %v to TLS connection object", conn)
	}

	// TLS Handshake
	if err := tlsconn.Handshake(); err != nil {
		return tlsconn, err
	}

	// Marshal connection certificate
	cert := tlsconn.ConnectionState().PeerCertificates[0]
	if cert == nil {
		return tlsconn, fmt.Errorf("Client did not provide a certificate")
	}

	if !l.Has(cert.PublicKey) {
		return tlsconn, fmt.Errorf("Connection cannot be verified")
	}

	// No error - certificate is verified
	return tlsconn, nil
}

// Checks if key is equal to the other key
func (k Key) EqualBytes(key []byte) bool {
	return bytes.Equal(k, key)
}
