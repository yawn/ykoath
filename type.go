// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import "fmt"

const (

	// Hotp describes HMAC based one-time passwords (https://tools.ietf.org/html/rfc4226)
	Hotp Type = 0x10

	// Totp describes time-based one-time passwords (https://tools.ietf.org/html/rfc6238)
	Totp Type = 0x20
)

// Type denotes the kind of derivation used for the one-time password
type Type byte

// String returns a string representation of the type
func (t Type) String() string {
	switch t {
	case Hotp:
		return "HOTP"
	case Totp:
		return "TOTP"
	default:
		return fmt.Sprintf("unknown %x", byte(t))
	}
}
