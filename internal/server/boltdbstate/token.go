package boltdbstate

import (
	"crypto/subtle"

	"github.com/pkg/errors"
	"golang.org/x/crypto/blake2b"
)

// TokenSignature generates a secure hash signature for the given pb.Token, using the existing keyId.
// The token, keyId, and signature can later be presented to TokenSignatureVerify to
// determine if the signature was produced by us, using this method.
// TODO(izaak): fix comment (token body, not pb token)
func (s *State) TokenSignature(tokenBody []byte, keyId string) (signature []byte, err error) {
	// hmacKeySize is the size in bytes that the HMAC keys should be. Each key will contain this number of bytes
	// of data from rand.Reader
	var hmacKeySize = 32

	// Get the key material
	key, err := s.HMACKeyCreateIfNotExist(keyId, hmacKeySize)
	if err != nil {
		return nil, err
	}

	// Sign it
	h, err := blake2b.New256(key.Key)
	if err != nil {
		return nil, err
	}
	h.Write(tokenBody)

	return h.Sum(nil), nil
}

// TODO(izaak): comment
func (s *State) TokenSignatureVerify(tokenBody []byte, signature []byte, keyId string) (isValid bool, err error) {

	key, err := s.HMACKeyGet(keyId)
	if err != nil || key == nil {
		return false, errors.Errorf("unknown key id %q", keyId)
	}

	// Hash the token body using the HMAC key so that we can compare
	// with our signature to ensure this hasn't been tampered with.
	h, err := blake2b.New256(key.Key)
	if err != nil {
		return false, errors.Wrapf(err, "failed to create BLAKE2b checksum computing digest for key id %q", keyId)
	}

	h.Write(tokenBody)
	sum := h.Sum(nil)
	if subtle.ConstantTimeCompare(sum, signature) != 1 {
		return false, nil
	}

	// The compare is good - the token signature is valid.
	return true, nil
}
