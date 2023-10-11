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
	res, err := o.calculateAll()
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

		return o.calculate(key)
	}

	return code, nil
}

// calculate implements the "CALCULATE" instruction to fetch a single
// truncated TOTP response
func (o *OATH) calculate(name string) (string, error) {
	var (
		buf       = make([]byte, 8)
		timestamp = o.Clock().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, insCalculate, 0x00, 0x01,
		write(tagName, []byte(name)),
		write(tagChallenge, buf),
	)
	if err != nil {
		return "", err
	}

	for _, tv := range res {
		switch tv.tag {
		case tagTruncated:
			return otp(tv.value), nil

		default:
			return "", fmt.Errorf("%w (%#x)", errUnknownTag, tv.tag)
		}
	}

	return "", fmt.Errorf("%w: %x", errNoValuesFound, res)
}

// calculateAll implements the "CALCULATE ALL" instruction to fetch all TOTP
// tokens and their codes (or a constant indicating a touch requirement)
func (o *OATH) calculateAll() (map[string]string, error) {
	var (
		buf       = make([]byte, 8)
		codes     []string
		names     []string
		timestamp = o.Clock().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, insCalculateAll, 0x00, 0x01,
		write(0x74, buf),
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

		case tagTruncated:
			codes = append(codes, otp(tv.value))

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

// otp converts a value into a (6 or 8 digits) one-time password
func otp(value []byte) string {
	digits := value[0]
	code := binary.BigEndian.Uint32(value[1:])
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}
