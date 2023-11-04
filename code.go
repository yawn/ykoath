// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"encoding/binary"
	"fmt"
)

type Code struct {
	Hash          []byte
	Digits        int
	Type          Type
	TouchRequired bool
	Truncated     bool
}

// OTP converts a value into a (6 or 8 digits) one-time password
// See: RFC 4226 Section 5.3 - Generating an HOTP Value
// https://datatracker.ietf.org/doc/html/rfc4226#section-5.3
func (c Code) OTP() string {
	var code uint32
	if c.Truncated {
		code = binary.BigEndian.Uint32(c.Hash)
	} else {
		hl := len(c.Hash)
		o := c.Hash[hl-1] & 0xf
		code = binary.BigEndian.Uint32(c.Hash[o:o+4]) & ^uint32(1<<31)
	}

	s := fmt.Sprintf("%08d", code)
	return s[len(s)-c.Digits:]
}
