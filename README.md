[![codecov](https://codecov.io/gh/gofika/bip32/branch/main/graph/badge.svg)](https://codecov.io/gh/gofika/bip32)
[![Build Status](https://github.com/gofika/bip32/workflows/build/badge.svg)](https://github.com/gofika/bip32)
[![go.dev](https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white)](https://pkg.go.dev/github.com/gofika/bip32)
[![Go Report Card](https://goreportcard.com/badge/github.com/gofika/bip32)](https://goreportcard.com/report/github.com/gofika/bip32)
[![Licenses](https://img.shields.io/github/license/gofika/bip32)](LICENSE)

# bip32

A pure Golang implementation of the BIP32 protocol that can derive paths and simultaneously supports both ECDSA and EdDSA signature algorithms.

* **ECDSA** uses `secp256k1` curve.
* **EdDSA** uses `ed25519` curve.


## Basic Usage

### Installation

To get the package, execute:

```bash
go get github.com/gofika/bip32
```

### Example

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/gofika/bip32"
)

func main() {
	seed, _ := hex.DecodeString("115fde209e8efb650ad8da2985f7b8bae495a4c45f6d6d7591242e53b0bbbcf91f4c1d2331cb0f7900929525282be1bf5eb9fb5c42f86ea0e1ded95224e24dda")
	key, err := bip32.NewExtendedKey(seed)
	if err != nil {
		panic(err)
	}

	{
		fmt.Println("Derive Path for: BTC:")
		key, err = bip32.DerivePath(key, "m/44'/0'/0'/0/0") // for BTC
		if err != nil {
			panic(err)
		}

		fmt.Println("ECPrivateKey:", hex.EncodeToString(key.ECPrivateKey().Serialize()))
		fmt.Println("ECPublicKey:", hex.EncodeToString(key.ECPublicKey().SerializeCompressed()))
	}
	fmt.Println("----------------------------------------")
	{
		fmt.Println("Derive Path for NEAR:")
		key, err = bip32.DerivePath(key, "m/44'/397'/0'") // for NEAR
		if err != nil {
			panic(err)
		}
		fmt.Println("EDPrivateKey:", hex.EncodeToString(key.EDPrivateKey()))
		fmt.Println("EDPublicKey:", hex.EncodeToString(key.EDPublicKey()))
	}
}

// Output:
// Derive Path for: BTC:
// ECPrivateKey: e8129373fad78817e7e8bad0bc84ae1309bf365142f9226679a43f8d485e46f1
// ECPublicKey: 02981ccbd66185f1b333b4f599ce6d58e8e37e17740431218c0fae9f678828c662
// ----------------------------------------
// Derive Path for NEAR:
// EDPrivateKey: fe8dae982f9537863688b32553c6c4e327352b352a0aa77d2c3fea56dc368e676c7af4bc88994106e324d421d505cfac45f3272b4513155474536d3c49e4ef6f
// EDPublicKey: 6c7af4bc88994106e324d421d505cfac45f3272b4513155474536d3c49e4ef6f

```