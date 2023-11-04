// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var (
	ErrNoValuesFound         = errors.New("no values found in response")
	ErrUnknownName           = errors.New("no such name configured")
	ErrMultipleMatches       = errors.New("multiple matches found")
	ErrTouchRequired         = errors.New("touch required")
	ErrTouchCallbackRequired = errors.New("touch callback required")
	ErrChallengeRequired     = errors.New("challenge required")
)

// Calculate is a high-level function that first identifies all TOTP credentials
// that are configured and returns the matching one (if no touch is required) or
// fires the callback and then fetches the name again while blocking during
// the device awaiting touch
func (c *Card) Calculate(name string, touchRequiredCallback func(string) error) (string, error) {
	totpChallenge := c.totpChallenge()

	codes, err := c.calculateAll(totpChallenge, true)
	if err != nil {
		return "", err
	}

	// Support matching by name without issuer in the same way that ykman does
	// https://github.com/Yubico/yubikey-manager/blob/f493008d78a0ad09016f23dabd1cb658929d9c0e/ykman/cli/oath.py#L543
	var key string
	var code Code
	var matches []string
	for k, c := range codes {
		if strings.Contains(strings.ToLower(k), strings.ToLower(name)) {
			key = k
			code = c
			matches = append(matches, k)
		}
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("%w: %s", ErrMultipleMatches, strings.Join(matches, ","))
	}

	if key == "" {
		return "", fmt.Errorf("%w: %s", ErrUnknownName, name)
	}

	if code.TouchRequired || code.Type == Hotp {
		if code.TouchRequired {
			if touchRequiredCallback == nil {
				return "", ErrTouchCallbackRequired
			}

			if err := touchRequiredCallback(key); err != nil {
				return "", err
			}
		}

		var challenge []byte
		if code.Type == Totp {
			challenge = totpChallenge
		}

		if code, err = c.calculate(key, challenge, true); err != nil {
			return "", err
		}
	}

	return code.OTP(), nil
}

func (c *Card) CalculateDirect(name string) (string, error) {
	d, err := c.calculate(name, c.totpChallenge(), true)
	if err != nil {
		return "", err
	}

	return d.OTP(), nil
}

func (c *Card) CalculateRaw(name string, challenge []byte) ([]byte, int, error) {
	d, err := c.calculate(name, challenge, false)
	if err != nil {
		return nil, -1, err
	}

	return d.Hash, d.Digits, nil
}

// calculate implements the "CALCULATE" instruction
func (c *Card) calculate(name string, challenge []byte, truncate bool) (Code, error) {
	var trunc byte
	if truncate {
		trunc = 0x01
	}

	tvs, err := c.send(insCalculate, 0x00, trunc,
		tlv.New(tagName, []byte(name)),
		tlv.New(tagChallenge, challenge),
	)
	if err != nil {
		return Code{}, err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagResponse, tagTruncated:
			digits := int(tv.Value[0])
			hash := tv.Value[1:]
			return Code{
				Hash:      hash,
				Digits:    digits,
				Truncated: tv.Tag == tagTruncated,
			}, nil

		default:
			return Code{}, fmt.Errorf("%w: %x", errUnknownTag, tv.Tag)
		}
	}

	return Code{}, ErrNoValuesFound
}

// calculateAll implements the "CALCULATE ALL" instruction to fetch all TOTP
// tokens and their codes (or a constant indicating a touch requirement)
func (c *Card) calculateAll(challenge []byte, truncate bool) (map[string]Code, error) {
	var (
		codes []Code
		names []string

		trunc byte
	)

	if truncate {
		trunc = 0x01
	}

	tvs, err := c.send(insCalculateAll, 0x00, trunc,
		tlv.New(tagChallenge, challenge),
	)
	if err != nil {
		return nil, err
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagName:
			names = append(names, string(tv.Value))

		case tagTouch:
			codes = append(codes, Code{
				Type:          Totp,
				TouchRequired: true,
			})

		case tagResponse, tagTruncated:
			codes = append(codes, Code{
				Type:      Totp,
				Hash:      tv.Value[1:],
				Digits:    int(tv.Value[0]),
				Truncated: tv.Tag == tagTruncated,
			})

		case tagHOTP:
			codes = append(codes, Code{
				Type: Hotp,
			})

		default:
			return nil, fmt.Errorf("%w (%#x)", errUnknownTag, tv.Tag)
		}
	}

	all := make(map[string]Code, len(names))

	for idx, name := range names {
		all[name] = codes[idx]
	}

	return all, nil
}

func (c *Card) totpChallenge() []byte {
	counter := c.Clock().Unix() / int64(c.Timestep.Seconds())
	return binary.BigEndian.AppendUint64(nil, uint64(counter))
}
