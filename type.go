package ykoath

import "fmt"

const (

	// Hotp describes HMAC based one-time passwords (https://tools.ietf.org/html/rfc4226)
	Hotp Type = typeHOTP

	// Totp describes time-based one-time passwords (https://tools.ietf.org/html/rfc6238)
	Totp Type = typeTOTP
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
