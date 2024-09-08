package bip32

import (
	"crypto/ed25519"
	"encoding/binary"
	"math/big"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
)

// Derive derive a child key from a parent key
//
// Example:
//
//	// drive path: "m/44'/0'/0'/0/0"
//	key, err := key.Derive(0x8000002C) // 44'
//	key, err := key.Derive(0x80000000) // 0'
//	key, err := key.Derive(0x80000000) // 0'
//	key, err := key.Derive(0)          // 0
//	key, err := key.Derive(0) // 0
func Derive(key *ExtendedKey, childIndex uint32) (*ExtendedKey, error) {
	childKey := &ExtendedKey{}

	// ECDSA
	{
		// Check if it's a hardened key
		isHardened := childIndex >= 1<<31
		var data []byte
		if isHardened {
			// Hardened child: data = 0x00 || ser256(parent.Key) || ser32(childIndex)
			data = make([]byte, 1+PrivateKeySize+4)
			copy(data[1:], key.ecKey)
			binary.BigEndian.PutUint32(data[1+PrivateKeySize:], childIndex)
		} else {
			// Normal child: data = serP(point(parent.Key)) || ser32(childIndex)
			publicKey := generatePublicKey(key.ecKey)
			data = make([]byte, 33+4)
			copy(data, publicKey)
			binary.BigEndian.PutUint32(data[33:], childIndex)
		}

		// Calculate I = HMAC-SHA512(Key = parent.ChainCode, Data = data)
		I := hmacSHA512(key.ecChainCode, data)
		il, ir := I[:32], I[32:]

		// Check if parse256(IL) >= n or ki = 0
		ilInt := new(big.Int).SetBytes(il)
		if ilInt.Cmp(curveOrder()) >= 0 || ilInt.Sign() == 0 {
			return nil, ErrInvalidChild
		}

		// ki = parse256(IL) + parent.Key (mod n)
		parentKeyInt := new(big.Int).SetBytes(key.ecKey)
		ki := new(big.Int).Add(ilInt, parentKeyInt)
		ki.Mod(ki, curveOrder())

		childKey.ecKey = ki.Bytes()
		childKey.ecChainCode = ir
		childKey.ecPrivateKey, childKey.ecPublicKey = btcec.PrivKeyFromBytes(childKey.ecKey)
	}

	// EdDSA
	{
		data := make([]byte, 1+PrivateKeySize+4)
		copy(data[1:], key.edKey)
		binary.BigEndian.PutUint32(data[1+PrivateKeySize:], childIndex)

		I := hmacSHA512(key.edChainCode, data)
		il, ir := I[:32], I[32:]

		childKey.edKey = il
		childKey.edChainCode = ir
		childKey.edPrivateKey = ed25519.NewKeyFromSeed(childKey.edKey)
		childKey.edPublicKey = childKey.edPrivateKey.Public().(ed25519.PublicKey)
	}

	return childKey, nil
}

// DerivePath Derive key based on the Derivation Path
//
// Example:
//
//	key, err := DerivePath(key, "m/44'/0'/0'/0/0") // for Bitcoin
//	key, err := DerivePath(key, "m/44'/1'/0'/0/0") // for Ethereum
func DerivePath(key *ExtendedKey, path string) (*ExtendedKey, error) {
	paths, err := ParsePath(path)
	if err != nil {
		return nil, err
	}
	return DerivePaths(key, paths)
}

// DerivePaths Derive keys based on the Derivation Paths
//
// Example:
//
//		paths := []uint32{
//			44 | bip32.HardenedKeyStart, // purpose 44
//			0 | bip32.HardenedKeyStart,  // 0 for Bitcoin
//			bip32.HardenedKeyStart,      // 0 for account
//			0,                           // 0 for change
//			0,                           // 0 for address
//		}
//
//	 key, err := DeriveByPaths(key, paths)
func DerivePaths(key *ExtendedKey, paths []uint32) (*ExtendedKey, error) {
	for _, childIdx := range paths {
		var err error
		key, err = Derive(key, childIdx)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

// ParsePath Parse the path to []uint32
//
// Example:
//
//	paths, err := ParsePath("m/44'/0'/0'/0/0") // [0x8000002c, 0x80000000, 0x80000000, 0, 0]
func ParsePath(path string) ([]uint32, error) {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return nil, ErrInvalidPath
	}
	if parts[0] != "m" {
		return nil, ErrInvalidPath
	}
	paths := []uint32{}
	for _, part := range parts[1:] {
		childIdx := uint32(0)
		if part[len(part)-1] == '\'' {
			childIdx = HardenedKeyStart
			part = part[:len(part)-1]
		}
		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, ErrInvalidPath
		}
		childIdx += uint32(idx)
		paths = append(paths, childIdx)
	}
	return paths, nil
}
