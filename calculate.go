// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

var (
	errNoValuesFound   = errors.New("no values found in response")
	errUnknownName     = errors.New("no such name configured")
	errMultipleMatches = errors.New("multiple matches found")
	errTouchRequired   = errors.New("touch-required")
)

// Calculate is a high-level function that first identifies all TOTP credentials
// that are configured and returns the matching one (if no touch is required) or
// fires the callback and then fetches the name again while blocking during
// the device awaiting touch
func (o *OATH) Calculate(name string, touchRequiredCallback func(string) error) (string, error) {
	res, err := o.calculateAll(o.totpChallenge(), true)
	if err != nil {
		return "", err
	}

	// Support matching by name without issuer in the same way that ykman does
	// https://github.com/Yubico/yubikey-manager/blob/f493008d78a0ad09016f23dabd1cb658929d9c0e/ykman/cli/oath.py#L543
	var key, code string
	var matches []string
	for k, c := range res {
		if strings.Contains(strings.ToLower(k), strings.ToLower(name)) {
			key = k
			code = c
			matches = append(matches, k)
		}
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("%w: %s", errMultipleMatches, strings.Join(matches, ","))
	}

	if key == "" {
		return "", fmt.Errorf("%w: %s", errUnknownName, name)
	}

	if code == errTouchRequired.Error() {
		if err := touchRequiredCallback(name); err != nil {
			return "", err
		}

		pw, digits, err := o.calculate(key, o.totpChallenge(), true)
		if err != nil {
			return "", err
		}

		return otp(digits, pw), nil
	}

	return code, nil
}

func (o *OATH) CalculateTOTP(name string) ([]byte, int, error) {
	return o.CalculateHOTP(name, o.totpChallenge())
}

func (o *OATH) CalculateHOTP(name string, challenge []byte) ([]byte, int, error) {
	return o.calculate(name, challenge, false)
}

// calculate implements the "CALCULATE" instruction
func (o *OATH) calculate(name string, challenge []byte, truncate bool) ([]byte, int, error) {
	var trunc byte
	if truncate {
		trunc = 0x01
	}

	res, err := o.send(0x00, insCalculate, 0x00, trunc,
		write(tagName, []byte(name)),
		write(tagChallenge, challenge),
	)
	if err != nil {
		return nil, 0, err
	}

	for _, tv := range res {
		switch tv.tag {
		case tagResponse, tagTruncated:
			digits := int(tv.value[0])
			hash := tv.value[1:]
			return hash, digits, nil

		default:
			return nil, 0, fmt.Errorf("%w: %x", errUnknownTag, tv.tag)
		}
	}

	return nil, 0, fmt.Errorf("%w: %x", errNoValuesFound, res)
}

// calculateAll implements the "CALCULATE ALL" instruction to fetch all TOTP
// tokens and their codes (or a constant indicating a touch requirement)
func (o *OATH) calculateAll(challenge []byte, truncate bool) (map[string]string, error) {
	var (
		codes []string
		names []string

		trunc byte
	)

	if truncate {
		trunc = 0x01
	}

	res, err := o.send(0x00, insCalculateAll, 0x00, trunc,
		write(tagChallenge, challenge),
	)
	if err != nil {
		return nil, err
	}

	for _, tv := range res {
		switch tv.tag {
		case tagName:
			names = append(names, string(tv.value))

		case tagTouch:
			codes = append(codes, errTouchRequired.Error())

		case tagResponse, tagTruncated:
			digits := int(tv.value[0])
			hash := tv.value[1:]
			codes = append(codes, otp(digits, hash))

		default:
			return nil, fmt.Errorf("%w (%#x)", errUnknownTag, tv.tag)
		}
	}

	all := make(map[string]string, len(names))

	for idx, name := range names {
		all[name] = codes[idx]
	}

	return all, nil
}

func (o *OATH) totpChallenge() []byte {
	counter := o.Clock().Unix() / int64(o.Timestep.Seconds())
	return binary.BigEndian.AppendUint64(nil, uint64(counter))
}

// otp converts a value into a (6 or 8 digits) one-time password
func otp(digits int, hash []byte) string {
	code := binary.BigEndian.Uint32(hash)
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}
