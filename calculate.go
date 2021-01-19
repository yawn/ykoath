package ykoath

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
)

const (
	errNoValuesFound   = "no values found in response (% x)"
	errUnknownName     = "no such name configued (%s)"
	errMultipleMatches = "multiple matches found (%s)"
	touchRequired      = "touch-required"
)

// NoTouchCallback performas a noop for users that have no touch support
func NoTouchCallback(_ string) error {
	return nil
}

// ErrorTouchCallback raises an error for users that have no touch support
func ErrorTouchCallback(_ string) error {
	return fmt.Errorf("requires touch but no callback specified")
}

// Calculate is a high-level function that first identifies all TOTP credentials
// that are configured and returns the matching one (if no touch is required) or
// fires the callback and then fetches the name again while blocking during
// the device awaiting touch
func (o *OATH) Calculate(name string, touchRequiredCallback func(string) error) (string, error) {
	res, err := o.CalculateAll()

	if err != nil {
		return "", nil
	}

	// support matching by name without issuer in the same way that ykman does
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
		return "", fmt.Errorf(errMultipleMatches, strings.Join(matches, ","))
	}

	if key == "" {
		return "", fmt.Errorf(errUnknownName, name)
	}

	if code == touchRequired {

		if err := touchRequiredCallback(name); err != nil {
			return "", err
		}

		return o.CalculateOne(key)

	}

	return code, nil

}

// CalculateOne implements the "CALCULATE" instruction to fetch a single
// truncated TOTP response
func (o *OATH) CalculateOne(name string) (string, error) {

	var (
		buf       = make([]byte, 8)
		timestamp = o.Clock().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, instCalculate, 0x00, rsTruncatedResponse,
		write(tagName, []byte(name)),
		write(tagChallenge, buf),
	)

	if err != nil {
		return "", err
	}

	for _, tv := range res {

		switch tv.tag {

		case tagTruncatedResponse:
			return otp(tv.value), nil

		default:
			return "", fmt.Errorf(errUnknownTag, tv.tag)
		}

	}

	return "", fmt.Errorf(errNoValuesFound, res)

}

// CalculateAll implements the "CALCULATE ALL" instruction to fetch all TOTP
// tokens and their codes (or a constant indicating a touch requirement)
func (o *OATH) CalculateAll() (map[string]string, error) {

	var (
		buf       = make([]byte, 8)
		codes     []string
		names     []string
		timestamp = o.Clock().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, instCalculateAll, 0x00, rsTruncatedResponse,
		write(tagChallenge, buf),
	)

	if err != nil {
		return nil, err
	}

	for _, tv := range res {

		switch tv.tag {

		case tagName:
			names = append(names, string(tv.value))

		case tagTouch:
			codes = append(codes, touchRequired)

		case tagResponse:
			o.Debug("tag no full response: %x", tv.value)
			return nil, fmt.Errorf("unable to handle full response %x", tv.value)

		case tagTruncatedResponse:
			codes = append(codes, otp(tv.value))

		case tagNoResponse:
			o.Debug("tag no response. Is HOTP %x", tv.value)
			return nil, fmt.Errorf("unable to handle HOTP response %x", tv.value)

		default:
			return nil, fmt.Errorf(errUnknownTag, tv.tag)
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
	digits := int(value[0])
	code := binary.BigEndian.Uint32(value[1:])
	// Limit code to a maximum number of digits
	code = code % uint32(math.Pow(10.0, float64(digits)))
	// Format as string with a minimum number of digits, padded with 0s
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code)
}
