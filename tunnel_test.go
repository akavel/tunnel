package tunnel

import (
	"bytes"
	"crypto/tls"
	"fmt"
	. "testing"
)

func TestFull(t *T) {
	pair1, err := Keygen(SimpleCert{CommonName: "foo"})
	if err != nil {
		t.Fatal("Can't create keypair 1:", err.Error())
	}
	pair2, err := Keygen(SimpleCert{CommonName: "bar"})
	if err != nil {
		t.Fatal("Can't create keypair 2:", err.Error())
	}

	msgsrv := "helo server"
	msgcli := "helo clientone"

	port := uint(31222)
	go func() {
		err = Serve(port, pair1, pair2.Pub(), func(c *tls.Conn, err error) bool {
			if err != nil {
				t.Fatal("Error while serving:", err.Error())
				panic(err)
			}

			_, err = c.Write([]byte(msgsrv))
			if err != nil {
				panic(err)
			}

			buf := make([]byte, len(msgcli))
			_, err = c.Read(buf)
			if err != nil {
				panic(err)
			}

			if !bytes.Equal(buf, []byte(msgcli)) {
				t.Fatal("server: message from client not as expected")
			}
			return false
		})
		if err != nil {
			t.Fatal("Error trying to serve:", err.Error())
		}
	}()

	cliconn, err := Dial(fmt.Sprintf("127.0.0.1:%d", port), pair2, pair1.Pub())
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
}
