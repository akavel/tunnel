package tunnel

import (
	"crypto/tls"
	"log"
)

func ExampleDial() {
	pair1, err := Keygen("foo")
	if err != nil {
		log.Fatalf("Can't create keypair 1: %v", err)
	}
	pair2, err := Keygen("bar")
	if err != nil {
		log.Fatalf("Can't create keypair 2: %v", err)
	}

	conn, err := Dial("127.0.0.1:31222", pair2, pair1.Pub())
	if err != nil {
		log.Fatalf("Error connecting: %v", err)
	}

	var buf []byte
	_, err = conn.Read(buf)
	if err != nil {
		log.Fatalf("Error reading: %v", err)
	}

	msg := "hello from the client!"

	_, err = conn.Write([]byte(msg))
	if err != nil {
		log.Fatalf("Error writing: %v", err)
	}
}

func ExampleNewServer() {
	pair1, err := Keygen("foo")
	if err != nil {
		log.Fatalf("Can't create keypair 1: %v", err)
	}
	pair2, err := Keygen("bar")
	if err != nil {
		log.Fatalf("Can't create keypair 2: %v", err)
	}

	msg := "hello from the server!"

	handler := func(c *tls.Conn) {
		// Write a Message to the Client
		if _, err := c.Write([]byte(msg)); err != nil {
			log.Fatalf("server: error writing message: %v", err)
			return
		}

		// Read a Message from the Client
		var buf []byte
		if _, err := c.Read(buf); err != nil {
			log.Fatalf("server: error reading message: %v", err)
			return
		}
	}

	server := NewServer(pair1, pair2.Pub(), handler)

	// Add Public Key
	// server.KeyList.Add(otherPublicKey)

	err = server.Listen("127.0.0.1:31222")
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
}
