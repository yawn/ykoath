package ykoath

import (
	"encoding/binary"
	"fmt"
)

const (
	errNoValuesFound = "no values found in response (% x)"
	errUnknownName   = "no such name configued (%s)"
	touchRequired    = "touch-required"
)

// Calculate is a high-level function that first identifies all TOTP credentials
// that are configured and returns the matching one (if no touch is required) or
// fires the callback and then fetches the name again while blocking during
// the device awaiting touch
func (o *OATH) Calculate(name string, touchRequiredCallback func(string) error) (string, error) {

	res, err := o.calculateAll()

	if err != nil {
		return "", nil
	}

	code, ok := res[name]

	if !ok {
		return "", fmt.Errorf(errUnknownName, name)
	}

	if code == touchRequired {

		if err := touchRequiredCallback(name); err != nil {
			return "", err
		}

		return o.calculate(name)

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

	res, err := o.send(0x00, 0xa2, 0x00, 0x01,
		write(0x71, []byte(name)),
		write(0x74, buf),
	)

	if err != nil {
		return "", err
	}

	for tag, values := range res {

		value := values[0]

		switch tag {

		case 0x76:
			return otp(value), nil

		default:
			return "", fmt.Errorf(errUnknownTag, tag)
		}

	}

	return "", fmt.Errorf(errNoValuesFound, res)

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

	res, err := o.send(0x00, 0xa4, 0x00, 0x01,
		write(0x74, buf),
	)

	if err != nil {
		return nil, err
	}

	for tag, values := range res {

		for _, value := range values {

			switch tag {

			case 0x71:
				names = append(names, string(value))

			case 0x7c:
				codes = append(codes, touchRequired)

			case 0x76:
				codes = append(codes, otp(value))

			default:
				return nil, fmt.Errorf(errUnknownTag, tag)
			}

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
