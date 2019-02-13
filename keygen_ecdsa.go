package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
)

type ecdsaKeyGenerator struct {
	algorithm      crypto.Hash
	privateKey     *ecdsa.PrivateKey
	publicKey      *ecdsa.PublicKey
	privateKeyPath string
	publicKeyPath  string
}

// NewECDSAKeyGenerator creates a new instance of a KeyGenerator using ecdsa cryptographic algorithms
// for key generation.
func NewECDSAKeyGenerator(algorithm crypto.Hash, savePath, filename string) KeyGenerator {
	kg := &ecdsaKeyGenerator{
		algorithm:      algorithm,
		privateKeyPath: filepath.Join(savePath, filename),
		publicKeyPath:  filepath.Join(savePath, filename+pubkeyExtension),
	}

	return kg
}

// DoesKeyExist checks to see if the current public and private key files already exist.
func (kg *ecdsaKeyGenerator) DoesKeyExist() bool {
	if _, err := os.Stat(kg.privateKeyPath); os.IsNotExist(err) {
		return false
	}

	if _, err := os.Stat(kg.privateKeyPath); os.IsNotExist(err) {
		return false
	}

	return true
}

func (kg *ecdsaKeyGenerator) loadKey() error {
	pemPrivKeyData, err := ioutil.ReadFile(kg.privateKeyPath)
	if err != nil {
		return fmt.Errorf("error reading private key file from path %s: %+v", kg.privateKeyPath, err)
	}

	blockPriv, _ := pem.Decode(pemPrivKeyData)
	decodedPrivKey, err := x509.ParseECPrivateKey(blockPriv.Bytes)
	if err != nil {
		return fmt.Errorf("error decoding private key file: %+v", err)
	}

	pemPubKeyData, err := ioutil.ReadFile(kg.publicKeyPath)
	if err != nil {
		return fmt.Errorf("error reading public key file from path %s: %+v", kg.publicKeyPath, err)
	}

	blockPub, _ := pem.Decode(pemPubKeyData)
	decodedPubKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return fmt.Errorf("error decoding public key file: %+v", err)
	}

	kg.privateKey = decodedPrivKey

	if pubKey, ok := decodedPubKey.(*ecdsa.PublicKey); ok {
		kg.publicKey = pubKey
	}

	if !reflect.DeepEqual(decodedPrivKey.PublicKey, kg.privateKey.PublicKey) {
		return fmt.Errorf("mismatching public keys")
	}

	return nil
}

// GenerateKey generates a public/private key using ECDSA.
func (kg *ecdsaKeyGenerator) GenerateKey() error {
	if kg.DoesKeyExist() {
		return kg.loadKey()
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return fmt.Errorf("error encountered when generating ECDSA public/private keypair: %+v\n", err)
	}

	kg.privateKey = privateKey
	kg.publicKey = &privateKey.PublicKey
	return nil
}

// Encode encodes the ECDSA public and private key pair into a PEM encoded keyfile.
func (kg *ecdsaKeyGenerator) Encode() ([]byte, []byte, error) {
	encodedPrivKey, err := x509.MarshalECPrivateKey(kg.privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshaling EC private key: %+v", err)
	}

	encodedPubKey, err := x509.MarshalPKIXPublicKey(kg.publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshaling public key: %+v", err)
	}

	pemPrivKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedPrivKey})
	pemPubKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encodedPubKey})

	return pemPrivKey, pemPubKey, nil
}

// Save saves the private and public key data.
func (kg *ecdsaKeyGenerator) Save(privateKeyData []byte, publicKeyData []byte) error {
	if err := ioutil.WriteFile(kg.privateKeyPath, privateKeyData, 0600); err != nil {
		return fmt.Errorf("error writing private key to path %s: %+v", kg.privateKeyPath, err)
	}

	if err := ioutil.WriteFile(kg.publicKeyPath, publicKeyData, 0600); err != nil {
		return fmt.Errorf("error writing public key to path %s: %+v", kg.publicKeyPath, err)
	}

	return nil
}

// Signature signs the data using ECDSA crypto via a combination of
// the private key and sha-256 digest of the data.
func (kg *ecdsaKeyGenerator) Signature(data []byte) ([]byte, error) {
	h := kg.algorithm.New()
	h.Write(data)
	return kg.privateKey.Sign(reader, h.Sum(nil), kg.algorithm)
}
