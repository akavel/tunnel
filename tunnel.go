/*
Package tunnel eases creation of simple TLS connection over insecure network
between safe, fully controlled endpoints.
*/
package tunnel

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func pemEncode(typename string, bytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typename, Bytes: bytes})
}

// Private + public key information.
type KeyPair struct {
	pub, priv []byte
	decoded   tls.Certificate
}

// Generates a randomized 1024b RSA self-signed private+public key set.
// The key is not useful out of this package (e.g. in fully-fledged TLS),
// as it is set to be marked as expired by the time it is created.
func Keygen(name string) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: name string,
		},
		NotBefore: now, // dummy value
		NotAfter:  now, // dummy value
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return PEMDecode(
		pemEncode("CERTIFICATE", derBytes),
		pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv)))
}

// Load a private+public key pair from PEM-encoded serialized form.
func PEMDecode(pub, priv []byte) (*KeyPair, error) {
	decoded, err := tls.X509KeyPair(pub, priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{pub: pub, priv: priv, decoded: decoded}, nil
}

// Get the public part of the key pair.
func (pair KeyPair) Pub() *x509.Certificate {
	pub, err := x509.ParseCertificate(pair.decoded.Certificate[0])
	if err != nil {
		return nil // panic(err) // should not happen
	}
	return pub
}

// Serialize the private+public key pair using PEM encoding.
func (pair KeyPair) PEMEncoded() (pub, priv []byte) {
	return append([]byte(nil), pair.pub...), append([]byte(nil), pair.priv...)
}

func (pair KeyPair) Save(pubpath, privpath string) error {
	pubf, err := os.Create(pubpath)
	if err != nil {
		return err
	}
	defer pubf.Close()
	_, err = pubf.Write(pair.pub)
	if err != nil {
		return err
	}

	privf, err := os.OpenFile(privpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer privf.Close()
	_, err = privf.Write(pair.priv)
	if err != nil {
		return err
	}
	return nil
}

type ClientHandler func(*tls.Conn, error) (more bool)

func Serve(tcpPort uint, cert *KeyPair, otherPubKey *x509.Certificate, handler ClientHandler) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert.decoded},
		ClientAuth:   tls.RequireAnyClientCert, // Must be done on server
	}
	listener, err := tls.Listen("tcp", fmt.Sprintf(":%d", tcpPort), config)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		var tlsConn *tls.Conn
		if err == nil {
			tlsConn, err = verifyOtherSide(conn, otherPubKey)
		}
		//TODO: replace each 'handler()' with 'go handler()'?
		if !handler(tlsConn, err) {
			break
		}
	}
	return nil
}

func marshalPub(cert *x509.Certificate) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(cert.PublicKey)
}

func verifyOtherSide(conn net.Conn, otherPubKey *x509.Certificate) (*tls.Conn, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("Package internal error: cannot convert %v to TLS connection object", conn)
	}

	err := tlsConn.Handshake()
	if err != nil {
		return tlsConn, err
	}

	state := tlsConn.ConnectionState()
	pubKey, err := marshalPub(state.PeerCertificates[0])
	if err != nil {
		return tlsConn, err
	}

	expectedBytes, err := marshalPub(otherPubKey)
	if err != nil {
		return tlsConn, fmt.Errorf("Cannot marshal expected public key: %s", err.Error())
	}

	if !bytes.Equal(pubKey, expectedBytes) {
		return tlsConn, fmt.Errorf("Other side has public key different than what was expected - got:\n%x\nexpected:\n%x", pubKey, expectedBytes)
	}
	return tlsConn, nil
}

func Dial(serverAddr string, cert *KeyPair, otherPubKey *x509.Certificate) (*tls.Conn, error) {
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert.decoded},
		InsecureSkipVerify: true, // Must be done on client
	}
	conn, err := tls.Dial("tcp", serverAddr, config)
	if err != nil {
		return nil, err
	}
	tlsConn, err := verifyOtherSide(conn, otherPubKey)
	if err != nil {
		return tlsConn, err
	}
	return tlsConn, nil
}
