package main

// SignedIdentifier represents the output structure for a signed message.
type SignedIdentifier struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	PubKey    string `json:"pubkey"`
}
