/*
Package tunnel eases creation of simple TLS connection over insecure network
between safe, fully controlled endpoints.
*/
package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

// Private + public key information.
type KeyPair struct {
	pub, priv []byte
	cert      tls.Certificate
}

// Reads Public and Private key from files
func NewKeyPair(pubfilename, privfilename string) (*KeyPair, error) {
	// Open public key file
	pubfile, err := os.Open(pubfilename)
	if err != nil {
		return nil, fmt.Errorf("public key file open error: %v", err)
	}
	defer pubfile.Close()

	// Read public key
	pubkey, err := ioutil.ReadAll(pubfile)
	if err != nil {
		return nil, fmt.Errorf("public key read error: %v", err)
	}

	// Open private key file
	privfile, err := os.Open(privfilename)
	if err != nil {
		return nil, fmt.Errorf("private key file open error: %v", err)
	}
	defer privfile.Close()

	// Read private key
	privkey, err := ioutil.ReadAll(privfile)
	if err != nil {
		return nil, fmt.Errorf("private key read error: %v", err)
	}

	return PEMDecode(pubkey, privkey)
}

// Generates a randomized 1024b RSA self-signed private+public key set.
// The key is not useful out of this package (e.g. in fully-fledged TLS),
// as it is set to be marked as expired by the time it is created.
func Keygen(name string) (*KeyPair, error) {
	// Generates a 1024 bit RSA key
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}

	// Creates a x509 Certificate
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: new(big.Int).SetInt64(0),
		Subject: pkix.Name{
			CommonName: name,
		},
		NotBefore: now, // dummy value
		NotAfter:  now, // dummy value
	}

	// Marshals certificate to bytes
	certbytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return PEMDecode(
		pemEncode("CERTIFICATE", certbytes),
		pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	)
}

// Load a private+public key pair from PEM-encoded serialized form.
func PEMDecode(pub, priv []byte) (*KeyPair, error) {
	// Creates a TLS Certificate from public and private key
	cert, err := tls.X509KeyPair(pub, priv)
	if err != nil {
		return nil, err
	}
	return &KeyPair{pub: pub, priv: priv, cert: cert}, nil
}

// Get the public part of the key pair.
func (pair *KeyPair) Pub() *x509.Certificate {
	pub, err := x509.ParseCertificate(pair.cert.Certificate[0])
	if err != nil {
		return nil
	}
	return pub
}

// Serialize the private+public key pair using PEM encoding.
func (pair *KeyPair) PEMEncoded() (pub, priv []byte) {
	return append([]byte(nil), pair.pub...), append([]byte(nil), pair.priv...)
}

// Writes public and private key to files
func (pair *KeyPair) Save(pubfilename, privfilename string) (err error) {
	// Creates a public key file
	pubfile, err := os.Create(pubfilename)
	if err != nil {
		return
	}
	defer pubfile.Close()

	// Writes a public key to a file
	_, err = pubfile.Write(pair.pub)
	if err != nil {
		return
	}

	// Creates a private key file
	privfile, err := os.OpenFile(privfilename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	defer privfile.Close()

	// Writes a private key to a file
	_, err = privfile.Write(pair.priv)
	if err != nil {
		return
	}

	return
}

func pemEncode(typename string, bytes []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typename, Bytes: bytes})
}
