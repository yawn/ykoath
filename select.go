package ykoath

import (
	"fmt"
)

// Select encapsulates the results of the "SELECT" instruction
type Select struct {
	Algorithm []byte
	Challenge []byte
	Name      []byte
	Version   []byte
}

// Select sends a "SELECT" instruction, initializing the device for an OATH session
func (o *OATH) Select() (*Select, error) {

	res, err := o.send(0x00, 0xa4, 0x04, 0x00,
		[]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01},
	)

	if err != nil {
		return nil, err
	}

	s := new(Select)

	for _, tv := range res {
		switch tv.tag {
		case TAG_ALGORITHM:
			s.Algorithm = tv.value
		case TAG_CHALLENGE:
			s.Challenge = tv.value
		case TAG_NAME:
			s.Name = tv.value
		case TAG_VERSION:
			s.Version = tv.value
		default:
			return nil, fmt.Errorf(errUnknownTag, tv.tag)
		}

	}

	return s, nil

}
