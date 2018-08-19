package tlv

import (
	"bytes"
	"fmt"
)

type Error []byte

func (e Error) Error() string {

	if bytes.Equal(e, []byte{0x6a, 0x80}) {
		return "wrong syntax"
	} else if bytes.Equal(e, []byte{0x69, 0x84}) {
		return "no such object"
	}

	return fmt.Sprintf("unknown (% x)", []byte(e))

}
