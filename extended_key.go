package bip32

import (
	"crypto/ed25519"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	// RecommendedSeedLen is the recommended length in bytes for a seed
	// to a master node.
	RecommendedSeedLen = 32 // 256 bits

	// HardenedKeyStart is the index at which a hardened key starts.  Each
	// extended key has 2^31 normal child keys and 2^31 hardened child keys.
	// Thus the range for normal child keys is [0, 2^31 - 1] and the range
	// for hardened child keys is [2^31, 2^32 - 1].
	HardenedKeyStart = 0x80000000 // 2^31

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits

	// PrivateKeySize is the size in bytes of a private key
	PrivateKeySize = 32

	// ChainCodeSize is the size in bytes of a chain code
	ChainCodeSize = 32

	// PublicKeyCompressedLength is the size in bytes of a compressed public key
	PublicKeyCompressedLength = 33
)

var (
	// ErrInvalidPath indicates an invalid key path
	ErrInvalidPath = errors.New("invalid derivation path")

	// ErrInvalidChild indicates an invalid child key
	ErrInvalidChild = errors.New("the extended key at this index is invalid")

	// ErrInvalidSeedLength indicates an invalid seed length
	ErrInvalidSeedLength = errors.New("invalid seed length")
)

// ExtendedKey represents an extended private key
//
// doc: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
type ExtendedKey struct {
	// ECDSA
	ecKey        []byte
	ecChainCode  []byte
	ecPrivateKey *btcec.PrivateKey
	ecPublicKey  *btcec.PublicKey

	// EdDSA
	edKey        []byte
	edChainCode  []byte
	edPrivateKey ed25519.PrivateKey
	edPublicKey  ed25519.PublicKey
}

// NewExtendedKey creates a new ExtendedKey from a seed
func NewExtendedKey(seed []byte) (*ExtendedKey, error) {
	seedLength := len(seed)
	if seedLength < MinSeedBytes || seedLength > MaxSeedBytes {
		return nil, ErrInvalidSeedLength
	}

	ek := &ExtendedKey{}

	// ECDSA
	{
		I := hmacSHA512([]byte("Bitcoin seed"), seed)
		il, ir := I[:32], I[32:]
		ecPrivateKey, ecPublicKey := btcec.PrivKeyFromBytes(il)
		ek.ecKey = il
		ek.ecChainCode = ir
		ek.ecPrivateKey = ecPrivateKey
		ek.ecPublicKey = ecPublicKey
	}

	// EdDSA
	{
		I := hmacSHA512([]byte("ed25519 seed"), seed)
		il, ir := I[:32], I[32:]
		edPrivateKey := ed25519.NewKeyFromSeed(il)
		edPublicKey := edPrivateKey.Public().(ed25519.PublicKey)
		ek.edKey = il
		ek.edChainCode = ir
		ek.edPrivateKey = edPrivateKey
		ek.edPublicKey = edPublicKey
	}

	return ek, nil
}

// ECPrivateKey returns the ECDSA private key
func (ek *ExtendedKey) ECPrivateKey() *btcec.PrivateKey {
	return ek.ecPrivateKey
}

// ECPrivateKeyBytes returns the ECDSA private key in bytes
func (ek *ExtendedKey) ECPrivateKeyBytes() []byte {
	return ek.ecKey
}

// ECPublicKey returns the ECDSA public key
func (ek *ExtendedKey) ECPublicKey() *btcec.PublicKey {
	return ek.ecPublicKey
}

// EDPrivateKey returns the EdDSA private key
func (ek *ExtendedKey) EDPrivateKey() ed25519.PrivateKey {
	return ek.edPrivateKey
}

// EDPrivateKeyBytes returns the EdDSA private key in bytes
func (ek *ExtendedKey) EDPrivateKeyBytes() []byte {
	return ek.edKey
}

// EDPublicKey returns the EdDSA public key
func (ek *ExtendedKey) EDPublicKey() ed25519.PublicKey {
	return ek.edPublicKey
}
