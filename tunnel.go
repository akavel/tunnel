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
	"time"
)

type SimpleCert struct {
	CommonName string
	NotBefore  *time.Time // optional; defaults to: "5 min before cert was created"
	NotAfter   *time.Time // optional; defaults to: "year after cert was created"
}

func pemEncode(typename string, bytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typename, Bytes: bytes})
}

type KeyPair struct {
	pub, priv []byte
	decoded   tls.Certificate
}

func Keygen(simple SimpleCert) (*KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if simple.NotBefore == nil {
		simple.NotBefore = new(time.Time)
		*simple.NotBefore = now.Add(-5 * time.Minute).UTC()
	}
	if simple.NotAfter == nil {
		simple.NotAfter = new(time.Time)
		*simple.NotAfter = now.AddDate(1, 0, 0).UTC() // valid for 1 year.
	}

	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: simple.CommonName,
		},
		NotBefore: *simple.NotBefore,
		NotAfter:  *simple.NotAfter,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return PEMDecode(
		pemEncode("CERTIFICATE", derBytes),
		pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv)))
}

func PEMDecode(pub, priv []byte) (*KeyPair, error) {
	decoded, err := tls.X509KeyPair(pub, priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{pub: pub, priv: priv, decoded: decoded}, nil
}

func (pair KeyPair) Pub() *x509.Certificate {
	pub, err := x509.ParseCertificate(pair.decoded.Certificate[0])
	if err != nil {
		panic(err) // should not happen
	}
	return pub
}

func (pair KeyPair) PEMEncoded() (pub, priv []byte) {
	return append([]byte(nil), pair.pub...), append([]byte(nil), pair.priv...)
}

type ClientHandler func(*tls.Conn, error) (more bool)

func Serve(tcpPort uint, cert *KeyPair, otherPubKey *x509.Certificate, handler ClientHandler) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{cert.decoded},
		ClientAuth:   tls.RequireAnyClientCert, // Must be done on server
		//TODO: why above?
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
		if err != nil {
			if !handler(tlsConn, err) {
				break
			}
			continue
		}
		if !handler(tlsConn, nil) {
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
		//TODO: why above?
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
