package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

const (
	message = "this is a test"
	savePath = ""
	filename = "test"
)

var privKeyPath = filepath.Join(savePath, filename)
var pubKeyPath = filepath.Join(savePath, filename+pubkeyExtension)

const ecdsaPemPrivKey = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIF7wCDXyfsxSMCYiUpNDPZDi8LGbsptqxe6Oztt9+LfzoAoGCCqGSM49
AwEHoUQDQgAEi/BOem1ObTSOE2EipYCXfhFXcXQXjVuE5YyXEJAK8ip+vFZent4N
nNMYiPAJ6TOpVWfjY4cF3AsE/KS1AmnZMw==
-----END PRIVATE KEY-----
`

const ecdsaPemPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi/BOem1ObTSOE2EipYCXfhFXcXQX
jVuE5YyXEJAK8ip+vFZent4NnNMYiPAJ6TOpVWfjY4cF3AsE/KS1AmnZMw==
-----END PUBLIC KEY-----
`

var ecdsaTestKey *ecdsa.PrivateKey

type ecdsaSignature struct {
	R, S *big.Int
}

func init() {
	block, _ := pem.Decode([]byte(ecdsaPemPrivKey))
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic("could not create initial ecdsa private key")
	}

	ecdsaTestKey = key
}

func newTestKeyGenerator() *ecdsaKeyGenerator {
	return &ecdsaKeyGenerator{
		algorithm: crypto.SHA256,
		privateKey: ecdsaTestKey,
		publicKey: &ecdsaTestKey.PublicKey,
		privateKeyPath: privKeyPath,
		publicKeyPath: pubKeyPath,
	}
}

func writeTestKeys(t *testing.T) {
	if err := ioutil.WriteFile(privKeyPath, []byte(ecdsaPemPrivKey), 0600); err != nil {
		t.Fatalf("could not create private key pem file: %+v", err)
	}

	if err := ioutil.WriteFile(pubKeyPath, []byte(ecdsaPemPubKey), 0600); err != nil {
		t.Fatalf("could not create public key pem file: %+v", err)
	}
}

func removeTestKeys(t *testing.T) {
	if err := os.Remove(privKeyPath); err != nil {
		t.Fatalf("could not remove private key file: %+v", err)
	}

	if err := os.Remove(pubKeyPath); err != nil {
		t.Fatalf("could not remove public key file: %+v", err)
	}
}

func TestEcdsaKeyGenerator_DoesKeyExist_NoTempFiles(t *testing.T) {
	var kg = NewECDSAKeyGenerator(crypto.SHA256, savePath, filename)

	if kg.DoesKeyExist() {
		t.Errorf("expected keys to not exist")
	}
}

func TestEcdsaKeyGenerator_DoesKeyExist(t *testing.T) {
	var kg = NewECDSAKeyGenerator(crypto.SHA256, savePath, filename)

	writeTestKeys(t)
	defer removeTestKeys(t)

	if !kg.DoesKeyExist() {
		t.Errorf("expected keys to exist")
	}
}

func TestEcdsaKeyGenerator_GenerateKey(t *testing.T) {
	var kg = NewECDSAKeyGenerator(crypto.SHA256, savePath, filename)

	if err := kg.GenerateKey(); err != nil {
		t.Errorf("could not generate ecdsa key: %+v", err)
	}
}

func TestEcdsaKeyGenerator_Encode(t *testing.T) {
	var kg = newTestKeyGenerator()

	privKey, pubKey, err := kg.Encode()
	if err != nil {
		t.Errorf("could not encode private/public keys: %+v", err)
	}

	if ecdsaPemPrivKey != string(privKey) {
		t.Errorf("mismatching encoded private key")
	}

	if ecdsaPemPubKey != string(pubKey) {
		t.Errorf("mismatching encoded public key")
	}
}

func TestEcdsaKeyGenerator_Save(t *testing.T) {
	var kg = NewECDSAKeyGenerator(crypto.SHA256, savePath, filename)

	if err := kg.Save([]byte(ecdsaPemPrivKey), []byte(ecdsaPemPubKey)); err != nil {
		t.Errorf("failed to save key files: %+v", err)
	}
	defer removeTestKeys(t)

	savedPrivKeyData, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		t.Fatalf("could not read from private key file: %+v", err)
	}

	savedPubKeyData, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("could not read from public key file: %+v", err)
	}

	if ecdsaPemPrivKey != string(savedPrivKeyData) {
		t.Errorf("mismatching private key saved")
	}

	if ecdsaPemPubKey != string(savedPubKeyData) {
		t.Errorf("mismatching public key saved")
	}
}

func TestEcdsaKeyGenerator_Signature(t *testing.T) {
	var kg = newTestKeyGenerator()
	if _, err := kg.Signature([]byte(message)); err != nil {
		t.Errorf("could not sign message `%s`: %+v", message, err)
	}
}

func TestNewECDSAKeyGenerator_verify(t *testing.T) {
	var kg = newTestKeyGenerator()

	signature, err := kg.Signature([]byte(message))
	if err != nil {
		t.Errorf("could not sign message `%s`: %+v", message, err)
	}

	h := kg.algorithm.New()
	h.Write([]byte(message))
	digest := h.Sum(nil)
	sig := &ecdsaSignature{}
	if _, err := asn1.Unmarshal(signature, sig); err != nil {
		t.Errorf("poop")
	}

	if !ecdsa.Verify(kg.publicKey, digest, sig.R, sig.S) {
		t.Errorf("poop")
	}
}