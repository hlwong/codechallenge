package main

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
)

func main() {
	if len(os.Args[1:]) < 1 {
		fmt.Printf("need at least one command line argument for %s", path.Base(os.Args[0]))
		os.Exit(1)
	}

	message := os.Args[1]
	data := []byte(message)
	kg := NewECDSAKeyGenerator(crypto.SHA256, "/tmp", "id_ecdsa")

	err := kg.GenerateKey()
	if err != nil {
		fmt.Printf("%+v", err)
		os.Exit(1)
	}

	digest, err := kg.Signature(data)
	if err != nil {
		fmt.Printf("%+v", err)
		os.Exit(1)
	}

	pemPrivKey, pemPubKey, err := kg.Encode()
	if err != nil {
		fmt.Printf("%+v", err)
		os.Exit(1)
	}

	if err = kg.Save(pemPrivKey, pemPubKey); err != nil {
		fmt.Printf("%+v", err)
		os.Exit(1)
	}

	encodedDigest := base64.StdEncoding.EncodeToString(digest)
	pubKey := string(pemPubKey)
	identifier := &SignedIdentifier{
		Message:   message,
		Signature: encodedDigest,
		PubKey:    pubKey,
	}

	jsonData, err := json.MarshalIndent(identifier, "", "\t")
	if err != nil {
		fmt.Printf("error during json marshaling: %+v", err)
		os.Exit(1)
	}

	fmt.Print(string(jsonData))
	os.Exit(0)
}
