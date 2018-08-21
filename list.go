package ykoath

import (
	"fmt"
)

// Name encapsulates the result of the "LIST" instruction
type Name struct {
	Algorithm Algorithm
	Type      Type
	Name      string
}

// String returns a string representation of the algorithm
func (n *Name) String() string {
	return fmt.Sprintf("%s (%s %s)", n.Name, n.Algorithm, n.Type)
}

// List sends a "LIST" instruction, return a list of OATH credentials
func (o *OATH) List() ([]*Name, error) {

	var names []*Name

	res, err := o.send(0x00, 0xa1, 0x00, 0x00)

	if err != nil {
		return nil, err
	}

	for tag, values := range res {

		switch tag {
		case 0x72:

			for _, value := range values {

				name := &Name{
					Algorithm: Algorithm(value[0] & 0x0f),
					Name:      string(value[1:]),
					Type:      Type(value[0] & 0xf0),
				}

				names = append(names, name)

			}

		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	return names, nil

}
