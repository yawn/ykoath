package ykoath

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
)

// Validate the OATH with a provided key
func (o *OATH) Validate(s *Select, key []byte) (bool, error) {
	algo, err := s.Hash()
	if err != nil {
		return false, err
	}

	mac := hmac.New(algo, key)
	_, _ = mac.Write(s.Challenge)
	responseSum := mac.Sum(nil)

	randChallenge := make([]byte, 8)
	_, err = rand.Read(randChallenge)
	if err != nil {
		return false, err
	}
	mac = hmac.New(algo, key)
	_, _ = mac.Write(randChallenge)
	challengeSum := mac.Sum(nil)

	response := write(tagResponse, responseSum)
	challenge := write(tagChallenge, randChallenge)

	res, err := o.send(0x00, instValidate, 0x00, 0x00, response, challenge)
	if err != nil {
		return false, err
	}

	var result bool

	for _, tv := range res {
		switch tv.tag {
		case tagResponse:
			result = bytes.Equal(tv.value, challengeSum)
		default:
			return false, fmt.Errorf(errUnknownTag, tv.tag)
		}
	}

	if !result {
		return result, fmt.Errorf(errFailedChallenge)
	}

	return result, nil
}
