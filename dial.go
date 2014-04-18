package tunnel

import (
	"crypto/tls"
	"crypto/x509"
)

// Establishes a connection through TLS
func Dial(addr string, pair *KeyPair, cert *x509.Certificate) (*tls.Conn, error) {
	config := &tls.Config{
		Certificates:       []tls.Certificate{pair.cert},
		InsecureSkipVerify: true, // Must be done on client
	}

	// Dial through TLS
	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	keylist := NewKeyList(cert.PublicKey)

	// Verify connection certificate
	tlsconn, err := keylist.VerifyConn(conn)
	if err != nil {
		return tlsconn, err
	}

	// Return connection if successfully verified connection
	return tlsconn, nil
}
