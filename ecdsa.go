package bip32

import (
	"bytes"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
)

var (
	curve = btcec.S256()
)

func generatePublicKey(key []byte) []byte {
	return compressPublicKey(curve.ScalarBaseMult(key))
}

func compressPublicKey(x *big.Int, y *big.Int) []byte {
	var key bytes.Buffer

	// Write header; 0x2 for even y value; 0x3 for odd
	key.WriteByte(byte(0x2) + byte(y.Bit(0)))

	// Write X coord; Pad the key so x is aligned with the LSB. Pad size is key length - header size (1) - xBytes size
	xBytes := x.Bytes()
	for i := 0; i < (PublicKeyCompressedLength - 1 - len(xBytes)); i++ {
		key.WriteByte(0x0)
	}
	key.Write(xBytes)

	return key.Bytes()
}

// Helper function to return the order of the elliptic curve
func curveOrder() *big.Int {
	// This should be the actual order of the elliptic curve used
	// For secp256k1, this value is:
	// FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
	order, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	return order
}
