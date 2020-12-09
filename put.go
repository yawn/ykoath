package ykoath

import (
	"fmt"
)

const errNametooLong = "name too long (%d > 64)"

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (o *OATH) Put(name string, a Algorithm, t Type, digits uint8, key []byte, touch bool) error {

	if l := len(name); l > 64 {
		return fmt.Errorf(errNametooLong, l)
	}

	var (
		// High 4 bits is type, low 4 bits is algorithm
		alg = (MASK_TYPE|byte(a))&MASK_ALGO | byte(t)
		dig = byte(digits)
		prp []byte
	)

	if touch {
		prp = write(TAG_PROPERTY, []byte{PROP_REQUIRE_TOUCH})
	}

	_, err := o.send(0x00, INST_PUT, 0x00, 0x00,
		write(TAG_NAME, []byte(name)),
		write(TAG_KEY, []byte{alg, dig}, key),
		prp,
	)

	return err

}
