package ykoath

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"strings"
)

// Select encapsulates the results of the "SELECT" instruction
type Select struct {
	Algorithm []byte
	Challenge []byte
	Name      []byte
	Version   []byte
}

// Salt returns the selected salt
func (s Select) Salt() []byte {
	return s.Name
}

// Hash returns a Hash constructor for the algorithm
func (s Select) Hash() (func() hash.Hash, error) {
	// If no agorithm found, default to sha1
	if len(s.Algorithm) == 0 {
		return sha1.New, nil
	}
	switch s.Algorithm[0] {
	case algoHMACSHA1:
		return sha1.New, nil
	case algoHMACSHA256:
		return sha256.New, nil
	case algoHMACSHA512:
		return sha512.New, nil
	}
	return sha1.New, fmt.Errorf("unknown hash algoritm %x", s.Algorithm)
}

// DeviceID returns the selected device ID
func (s Select) DeviceID() string {
	h := sha256.New()
	_, _ = h.Write(s.Salt())
	sum := h.Sum(nil)
	sum = sum[:16]
	return strings.Replace(base64.StdEncoding.EncodeToString(sum), "=", "", -1)
}

// DeriveKey returns a key as a byte array from a given passphrase
func (s Select) DeriveKey(passphrase string) []byte {
	iters := 1000
	keyLength := 16
	return pbkdf2.Key([]byte(passphrase), s.Salt(), iters, keyLength, sha1.New)
}

// Select sends a "SELECT" instruction, initializing the device for an OATH session
func (o *OATH) Select() (*Select, error) {

	res, err := o.send(0x00, 0xa4, 0x04, 0x00,
		[]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01},
	)

	if err != nil {
		return nil, err
	}

	s := new(Select)

	for _, tv := range res {
		switch tv.tag {
		case tagAlgorithm:
			s.Algorithm = tv.value
		case tagChallenge:
			s.Challenge = tv.value
		case tagName:
			s.Name = tv.value
		case tagVersion:
			s.Version = tv.value
		default:
			return nil, fmt.Errorf(errUnknownTag, tv.tag)
		}

	}

	return s, nil

}
