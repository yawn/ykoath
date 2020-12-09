package ykoath

import (
	"crypto/hmac"
	"crypto/rand"
)

// Validate the OATH with a provided key
func (o *OATH) Validate(s *Select, key []byte) (bool, error) {
	algo, err := s.Hash()
	if err != nil {
		return false, err
	}

	mac := hmac.New(algo, key)
	mac.Write(s.Challenge)
	responseSum := mac.Sum(nil)

	randChallenge := make([]byte, 8)
	_, err = rand.Read(randChallenge)
	if err != nil {
		return false, err
	}
	mac = hmac.New(algo, key)
	mac.Write(randChallenge)
	challengeSum := mac.Sum(nil)

	response := write(TAG_RESPONSE, responseSum)
	challenge := write(TAG_CHALLENGE, challengeSum)
	_, err = o.send(0x00, INST_VALIDATE, 0x00, 0x00, response, challenge)
	if err != nil {
		return false, err
	}
	return true, nil
}
