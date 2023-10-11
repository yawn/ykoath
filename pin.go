// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

var errTokenResponse = errors.New("invalid token response")

func (o *OATH) RemoveCode() error {
	return o.SetCode(nil, HmacSha256)
}

// SetCode sets a new PIN.
// This command no authentication.
func (o *OATH) SetCode(code []byte, alg Algorithm) error {
	sel, err := o.Select()
	if err != nil {
		return err
	}

	key := pbkdf2.Key(code, sel.Name, 1000, 16, alg.Hash())

	myChallenge, err := getChallenge()
	if err != nil {
		return err
	}

	mac := hmac.New(alg.Hash(), key)
	mac.Write(myChallenge)
	myResponse := mac.Sum(nil)

	_, err = o.send(0x00, insSetCode, 0x00, 0x00,
		write(tagKey, []byte{byte(alg)}, key),
		write(tagChallenge, myChallenge),
		write(tagResponse, myResponse),
	)

	return err
}

// Reset resets the application to just-installed state.
// This command requires no authentication.
func (o *OATH) Validate(code []byte) error {
	var myChallenge, tokenResponse, tokenResponseExpected []byte

	sel, err := o.Select()
	if err != nil {
		return err
	}

	if len(sel.Algorithm) < 1 || len(sel.Name) < 1 {
		return errNoSuchObject
	}

	tokenChallenge := sel.Challenge
	alg := Algorithm(sel.Algorithm[0])
	key := pbkdf2.Key(code, sel.Name, 1000, 16, alg.Hash())

	mac := hmac.New(alg.Hash(), key)
	mac.Write(tokenChallenge)
	myResponse := mac.Sum(nil)

	myChallenge = make([]byte, 8)
	if _, err := rand.Read(myChallenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	res, err := o.send(0x00, insValidate, 0x00, 0x00,
		write(tagResponse, myResponse),
		write(tagChallenge, myChallenge),
	)
	if err != nil {
		return err
	}

	for _, tv := range res {
		if tv.tag == tagResponse {
			tokenResponse = tv.value
		}
	}

	if tokenResponse == nil {
		return errTokenResponse
	}

	mac.Reset()
	mac.Write(myChallenge)
	tokenResponseExpected = mac.Sum(nil)

	if !bytes.Equal(tokenResponse, tokenResponseExpected) {
		return errTokenResponse
	}

	return nil
}

func getChallenge() ([]byte, error) {
	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}
