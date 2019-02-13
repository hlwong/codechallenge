package main

import (
	"crypto/rand"
)

const pubkeyExtension = ".pub"
var reader = rand.Reader

// KeyEncoder is an interface for a method to encode public and private keys
// into an unspecified encoded format.
type KeyEncoder interface {
	Encode() ([]byte, []byte, error)
}

// KeySaver is an interface for method to save public and private keys.
type KeySaver interface {
	Save(privateKeyData []byte, publicKeyData []byte) error
}

// KeySigner is an interface for a signature using an unspecified cryptographic algorithm
// used to sign the data.
type KeySigner interface {
	Signature(data []byte) ([]byte, error)
}

// KeyGenerator an interface for a key generator, which can generate, sign, encode, and save
// for an unspecified cryptographic algorithm.
type KeyGenerator interface {
	DoesKeyExist() bool
	GenerateKey() error
	KeyEncoder
	KeySaver
	KeySigner
}
