package tunnel

import (
	"bytes"
	"crypto/tls"
	. "testing"
)

func TestFull(t *T) {
	// Test listen/dial address
	testaddr := "127.0.0.1:31222"

	pair1, err := Keygen("foo")
	if err != nil {
		t.Fatal("Can't create keypair 1:", err.Error())
	}
	pair2, err := Keygen("bar")
	if err != nil {
		t.Fatal("Can't create keypair 2:", err.Error())
	}

	msgsrv := "helo server"
	msgcli := "helo clientone"
	server := NewServer(pair1, pair2.Pub(), func(c *tls.Conn) {

		// Write a Message to the Client
		if _, err := c.Write([]byte(msgsrv)); err != nil {
			t.Errorf("server: error writing message: %v", err)
			return
		}

		// Read a Message from the Client
		buf := make([]byte, len(msgcli))
		if _, err := c.Read(buf); err != nil {
			t.Errorf("server: error reading message: %v", err)
			return
		}

		// Check if Message from the Client is the same as sent message
		if !bytes.Equal(buf, []byte(msgcli)) {
			t.Fatal("server: message from client not as expected")
		}
	})

	go func() {
		err := server.Listen(testaddr)
		if err != nil {
			t.Errorf("Error trying to serve: %v", err)
		}
	}()

	cliconn, err := Dial(testaddr, pair2, pair1.Pub())
	if err != nil {
		t.Fatal("Error connecting on client side:", err.Error())
		panic(err)
	}

	buf := make([]byte, len(msgsrv))
	_, err = cliconn.Read(buf)
	if err != nil {
		panic(err)
	}
	if !bytes.Equal(buf, []byte(msgsrv)) {
		t.Fatal("client: message from server not as expected")
	}

	_, err = cliconn.Write([]byte(msgcli))
	if err != nil {
		panic(err)
	}

	server.Close <- true
}
