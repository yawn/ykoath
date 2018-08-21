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

	for tag, values := range res {

		value := values[0]

		switch tag {
		case 0x7b:
			s.Algorithm = value
		case 0x74:
			s.Challenge = value
		case 0x71:
			s.Name = value
		case 0x79:
			s.Version = value
		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	return s, nil

}
