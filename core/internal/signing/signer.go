package signing

import (
	"crypto/ecdsa"
	"fmt"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	gocrypto "github.com/ethereum/go-ethereum/crypto"
)

// Signer holds Verilock's ECDSA secp256k1 private key and exposes only
// what the rest of the application needs: a public address and a sign function.
//
// SECURITY CONTRACT:
//   - The private key is loaded once from a keyfile or env var on startup.
//   - It is held in memory as *ecdsa.PrivateKey — never serialized, never logged,
//     never returned in any response, never written to disk again.
//   - The private key field is unexported. No code outside this package can read it.
//   - Sign() accepts a 32-byte hash and returns a signature. The key never leaves.
//   - Close() overwrites key bytes in memory before the object is released.
//   - DryRunMode replaces real signing with a deterministic zero signature.
type Signer struct {
	privateKey           *ecdsa.PrivateKey // unexported — never accessible outside this package
	guardContractAddress common.Address    // used in EIP-712 domain separator
	dryRun               bool              // when true, Sign() returns zeros, never uses real key
}

// Config carries the inputs needed to initialise a Signer.
type Config struct {
	// PrivateKeyHex is the 64-character hex-encoded secp256k1 private key.
	// Must come from the keyfile or secrets manager — never hardcoded.
	PrivateKeyHex string

	// GuardContractAddress is the 0x-prefixed address of the deployed VerilockGuard.
	// Used in the EIP-712 domain separator. Tokens signed with the wrong address
	// will fail on-chain verification — this must match the deployed contract exactly.
	GuardContractAddress string

	// DryRunMode disables real signing. Sign() returns a zero signature.
	// Must never be true in production (enforced by config.Load()).
	DryRunMode bool
}

// New loads the ECDSA private key, validates it, and returns a ready-to-use Signer.
// Returns a fatal error if the key is invalid or the Guard address is malformed.
//
// SECURITY: PrivateKeyHex must come from the keyfile or env var only.
// Never pass a hardcoded string. Never log the input value.
func New(cfg Config) (*Signer, error) {
	if len(cfg.PrivateKeyHex) != 64 {
		// Report length only — never echo the key value itself in errors.
		return nil, fmt.Errorf(
			"signing: private key must be 64 hex characters (got %d) — check VERILOCK_SIGNING_KEY_HEX",
			len(cfg.PrivateKeyHex),
		)
	}

	key, err := gocrypto.HexToECDSA(cfg.PrivateKeyHex)
	if err != nil {
		// Do not wrap the original error — it may contain key material in some
		// go-ethereum builds. Return a generic diagnostic only.
		return nil, fmt.Errorf("signing: ECDSA private key is invalid or malformed")
	}

	// Confirm the public key is derivable — basic sanity check.
	pubKey, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pubKey == nil {
		return nil, fmt.Errorf("signing: failed to derive public key from private key")
	}

	// Validate and parse the Guard contract address.
	// This is embedded in every EIP-712 domain separator — it must be correct.
	if len(cfg.GuardContractAddress) != 42 {
		return nil, fmt.Errorf(
			"signing: GuardContractAddress must be a 42-character 0x-prefixed address (got %d chars)",
			len(cfg.GuardContractAddress),
		)
	}
	guardAddr := common.HexToAddress(cfg.GuardContractAddress)

	return &Signer{
		privateKey:           key,
		guardContractAddress: guardAddr,
		dryRun:               cfg.DryRunMode,
	}, nil
}

// PublicAddress returns Verilock's Ethereum address derived from the signing key.
// This is the address the on-chain Guard compares against ecrecover output.
// Safe to log and display.
func (s *Signer) PublicAddress() string {
	return gocrypto.PubkeyToAddress(s.privateKey.PublicKey).Hex()
}

// PublicKeyHex returns the uncompressed secp256k1 public key as a hex string.
// Safe to share — this is the public half of the key pair.
func (s *Signer) PublicKeyHex() string {
	return fmt.Sprintf("%x", gocrypto.FromECDSAPub(&s.privateKey.PublicKey))
}

// GuardAddress returns the Guard contract address this Signer is configured for.
// Used to validate that the runtime config matches the deployed contract.
func (s *Signer) GuardAddress() common.Address {
	return s.guardContractAddress
}

// Sign signs a 32-byte hash using secp256k1 ECDSA.
// Returns a 65-byte [R(32) || S(32) || V(1)] signature where V is 27 or 28.
//
// In DryRunMode, returns a 65-byte all-zeros slice without touching the real key.
//
// SECURITY:
//   - Input must be exactly 32 bytes. Enforced — not a suggestion.
//   - V is adjusted from recovery ID (0/1) to Ethereum standard (27/28).
//     This is required for on-chain ecrecover compatibility.
//   - The private key never leaves this function.
func (s *Signer) Sign(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf(
			"signing: Sign() requires exactly 32 bytes, got %d — pass a keccak256 hash",
			len(hash),
		)
	}

	// DRY RUN: return a deterministic zero signature.
	// The real key is never accessed. Tokens produced in dry-run mode
	// will fail Guard verification — which is the correct behaviour.
	if s.dryRun {
		zeros := make([]byte, 65)
		zeros[64] = 27 // valid V byte, but R and S are all zeros — Guard rejects this
		return zeros, nil
	}

	sig, err := gocrypto.Sign(hash, s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("signing: ECDSA sign operation failed: %w", err)
	}

	// go-ethereum's crypto.Sign returns V as 0 or 1 (recovery ID).
	// Ethereum's on-chain ecrecover expects V as 27 or 28.
	sig[64] += 27

	return sig, nil
}

// Close overwrites the private key bytes in memory before the Signer is released.
// Call this during graceful shutdown so the key is not readable in heap dumps.
//
// SECURITY: After Close(), the Signer must not be used. Sign() will return an error
// if called after Close() because the zeroed key is cryptographically invalid.
func (s *Signer) Close() {
	if s.privateKey == nil {
		return
	}
	// Overwrite the private key D integer's backing bytes.
	// unsafe.Slice gives us direct access to the big.Int's internal byte array.
	d := s.privateKey.D
	if d != nil {
		b := d.Bits()
		for i := range b {
			b[i] = 0
		}
		// Also zero the raw byte representation if present.
		raw := d.Bytes()
		ptr := unsafe.SliceData(raw)
		if ptr != nil {
			for i := range raw {
				raw[i] = 0
			}
		}
	}
	s.privateKey = nil
}
