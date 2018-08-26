package ykoath

import (
	"fmt"
)

var errNametooLong = "name too long (%d > 64)"

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (o *OATH) Put(name string, a Algorithm, t Type, digits uint8, key []byte, touch bool) error {

	if l := len(name); l > 64 {
		return fmt.Errorf(errNametooLong, l)
	}

	var (
		alg = (0xf0|byte(a))&0x0f | byte(t)
		dig = byte(digits)
		prp []byte
	)

	if touch {
		prp = write(0x78, []byte{0x02})
	}

	_, err := o.send(0x00, 0x01, 0x00, 0x00,
		write(0x71, []byte(name)),
		write(0x73, []byte{alg, dig}, key),
		prp,
	)

	return err

}
