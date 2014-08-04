package jwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

type SigningMethodHS256 struct{}

func init() {
	RegisterSigningMethod("HS256", func() SigningMethod {
		return new(SigningMethodHS256)
	})
}

func (m *SigningMethodHS256) Alg() string {
	return "HS256"
}

func (m *SigningMethodHS256) Verify(signingString, signature string, key interface{}) (err error) {
	// Key
	var sig []byte
	if sig, err = DecodeSegment(signature); err == nil {
		hasher := hmac.New(sha256.New, key.([]byte))
		hasher.Write([]byte(signingString))

		if !bytes.Equal(sig, hasher.Sum(nil)) {
			err = errors.New("Signature is invalid")
		}
	}
	return
}

func (m *SigningMethodHS256) Sign(signingString string, key interface{}) (string, error) {
	hasher := hmac.New(sha256.New, key.([]byte))
	hasher.Write([]byte(signingString))

	return EncodeSegment(hasher.Sum(nil)), nil
}
