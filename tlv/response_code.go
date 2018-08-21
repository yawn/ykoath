package tlv

import (
	"bytes"
	"fmt"
)

// Error encapsulates (some) response codes from the spec
type Error []byte

// Error return the encapsulated error string
func (e Error) Error() string {

	if bytes.Equal(e, []byte{0x6a, 0x80}) {
		return "wrong syntax"
	} else if bytes.Equal(e, []byte{0x69, 0x84}) {
		return "no such object"
	}

	return fmt.Sprintf("unknown (% x)", []byte(e))

}
