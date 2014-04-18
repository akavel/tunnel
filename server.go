package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

// Connection Handler
type Handler func(*tls.Conn)

// TLS Server
type Server struct {
	*KeyPair
	Handler
	KeyList
	Close chan bool
}

// Creates a new TLS Server
func NewServer(pair *KeyPair, cert *x509.Certificate, handler Handler) *Server {
	// List of certificates (allowed to connect)
	certlist := make(KeyList)
	if cert != nil {
		certlist.Add(cert.PublicKey)
	}
	closechan := make(chan bool, 1)
	// Returns TLS Server
	return &Server{pair, handler, certlist, closechan}
}

// Starts a TLS Listener
func (s *Server) Listen(addr string) (err error) {
	config := &tls.Config{
		Certificates: []tls.Certificate{s.KeyPair.cert},
		ClientAuth:   tls.RequireAnyClientCert, // Must be done on server
	}

	// Starts TLS Listener
	listener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return
	}

	// Watch s.Close for signal to close listener
	go s.watchClose(listener)

	// Defer close of listener
	defer func() {
		s.Close <- true
	}()

	// Listener loop
	for {
		// Accepts TLS connection
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		// Verifies connection certificate
		tlsconn, err := s.KeyList.VerifyConn(conn)
		if err != nil {
			continue
		}

		go s.Handler(tlsconn)
	}
	return
}

func (s *Server) watchClose(listener net.Listener) {
	<-s.Close
	listener.Close()
}

func Serve(addr string, pair *KeyPair, cert *x509.Certificate, handler Handler) error {
	server := NewServer(pair, cert, handler)
	return server.Listen(addr)
}
