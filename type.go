package ykoath

import "fmt"

const (
	Hotp Type = 0x10
	Totp Type = 0x20
)

type Type byte

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
