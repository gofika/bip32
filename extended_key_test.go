package bip32

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtendedKey(t *testing.T) {
	seed, _ := hex.DecodeString("115fde209e8efb650ad8da2985f7b8bae495a4c45f6d6d7591242e53b0bbbcf91f4c1d2331cb0f7900929525282be1bf5eb9fb5c42f86ea0e1ded95224e24dda")
	key, err := NewExtendedKey(seed)
	assert.Nil(t, err)

	key, err = DerivePath(key, "m/44'/0'/0'/0/0")
	assert.Nil(t, err)

	assert.Equal(t, "e8129373fad78817e7e8bad0bc84ae1309bf365142f9226679a43f8d485e46f1", hex.EncodeToString(key.ECPrivateKey().Serialize()))
	assert.Equal(t, "02981ccbd66185f1b333b4f599ce6d58e8e37e17740431218c0fae9f678828c662", hex.EncodeToString(key.ECPublicKey().SerializeCompressed()))
	assert.Equal(t, "f352288a8be15bffe77a0b161d81ed70e1c33bb48d9d2a01ba9f0e4a8f8c182d7a4d4bdb208989049ba116295083db4720448528ff74158bddbc80c1f74963db", hex.EncodeToString(key.EDPrivateKey()))
	assert.Equal(t, "7a4d4bdb208989049ba116295083db4720448528ff74158bddbc80c1f74963db", hex.EncodeToString(key.EDPublicKey()))
}
