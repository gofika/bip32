package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
)

// hmacSHA512 calculates the HMAC-SHA512 of the given key and data
func hmacSHA512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
