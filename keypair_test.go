package tunnel

import (
	"bytes"
	"os"
	. "testing"
)

func TestKeygen(t *T) {
	pair, err := Keygen("foo")
	if err != nil {
		t.Errorf("Can't create keypair: %s", err)
		return
	}
	if !(len(pair.pub) > 1) {
		t.Error("Generated public key is empty")
	}

	if !(len(pair.priv) > 1) {
		t.Error("Generated private key is empty")
	}
}

func TestKeygenPub(t *T) {
	pair, err := Keygen("foo")
	if err != nil {
		t.Errorf("Can't create keypair: %s", err)
		return
	}

	if pair.Pub() == nil {
		t.Error("Can't get public key")
	}
}

func TestKeygenPEMEncoded(t *T) {
	pair, err := Keygen("foo")
	if err != nil {
		t.Errorf("Can't create keypair: %s", err)
		return
	}

	pub, priv := pair.PEMEncoded()
	if len(pub)-1 < 1 {
		t.Error("PEMEncoded did not encode public key")
	}

	if len(priv)-1 < 1 {
		t.Error("PEMEncoded did not encode private key")
	}
}

func TestKeygenSave(t *T) {
	pair, err := Keygen("foo")
	if err != nil {
		t.Errorf("Can't create keypair: %s", err)
		return
	}
	var (
		pubFile  = "./test.pem"
		privFile = "./test.key"
	)
	err = pair.Save(pubFile, privFile)
	if err != nil {
		t.Errorf("Can't save keypair: %s", err)
		return
	}
	stat, err := os.Stat(pubFile)
	if err != nil || !(stat.Size() > 1) {
		t.Error("Public file is not saved")
		return
	}

	stat, err = os.Stat(privFile)
	if err != nil || !(stat.Size() > 1) {
		t.Error("Private file is not saved")
		return
	}

	keys, err := NewKeyPair(pubFile, privFile)
	if err != nil {
		t.Errorf("Cannot load keypair from files: %v", err)
		return
	}

	if !bytes.Equal(keys.pub, pair.pub) {
		t.Errorf("Loaded public key doesn't match generated one")
		return
	}

	if !bytes.Equal(keys.priv, pair.priv) {
		t.Errorf("Loaded private key doesn't match generated one")
		return
	}

	// Remove test files
	os.Remove(pubFile)
	os.Remove(privFile)
}
