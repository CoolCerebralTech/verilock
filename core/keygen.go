package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// Generate ECDSA secp256k1 private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}
	privKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("=== COPY THESE INTO YOUR .env ===")
	fmt.Printf("\nTOLLGATE_SIGNING_KEY_HEX=%s\n", hex.EncodeToString(privKeyBytes))

	// Generate random 32-byte agent secret
	secret := make([]byte, 32)
	rand.Read(secret)
	fmt.Printf("AGENT_TOKEN_SECRET=%s\n", hex.EncodeToString(secret))

	// Also print the public key so you can verify later
	pubKey := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("\n(Tollgate public address: %s)\n", pubKey.Hex())
}
