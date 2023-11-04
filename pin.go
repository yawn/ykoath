// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
	"golang.org/x/crypto/pbkdf2"
)

var errTokenResponse = errors.New("invalid token response")

func (c *Card) RemoveCode() error {
	_, err := c.send(insSetCode, 0x00, 0x00, tlv.New(tagKey))
	return err
}

// SetCode sets a new PIN.
// This command no authentication.
func (c *Card) SetCode(code []byte, alg Algorithm) error {
	sel, err := c.Select()
	if err != nil {
		return err
	}

	key := pbkdf2.Key(code, sel.Name, 1000, 16, alg.Hash())

	myChallenge := make([]byte, 8)
	if _, err := c.Rand.Read(myChallenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	mac := hmac.New(alg.Hash(), key)
	mac.Write(myChallenge)
	myResponse := mac.Sum(nil)

	algKey := append([]byte{byte(alg)}, key...)

	_, err = c.send(insSetCode, 0x00, 0x00,
		tlv.New(tagKey, algKey),
		tlv.New(tagChallenge, myChallenge),
		tlv.New(tagResponse, myResponse),
	)
	return err
}

// Reset resets the application to just-installed state.
// This command requires no authentication.
func (c *Card) Validate(code []byte) error {
	var myChallenge, tokenResponse, tokenResponseExpected []byte

	sel, err := c.Select()
	if err != nil {
		return err
	}

	if len(sel.Algorithm) < 1 || len(sel.Name) < 1 {
		return ErrNoSuchObject
	}

	tokenChallenge := sel.Challenge
	alg := Algorithm(sel.Algorithm[0])
	key := pbkdf2.Key(code, sel.Name, 1000, 16, alg.Hash())

	mac := hmac.New(alg.Hash(), key)
	mac.Write(tokenChallenge)
	myResponse := mac.Sum(nil)

	myChallenge = make([]byte, 8)
	if _, err := c.Rand.Read(myChallenge); err != nil {
		return fmt.Errorf("failed to generate challenge: %w", err)
	}

	tvs, err := c.send(insValidate, 0x00, 0x00,
		tlv.New(tagResponse, myResponse),
		tlv.New(tagChallenge, myChallenge),
	)
	if err != nil {
		return err
	}

	for _, tv := range tvs {
		if tv.Tag == tagResponse {
			tokenResponse = tv.Value
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
