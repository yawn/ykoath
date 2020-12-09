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
	return fmt.Sprintf("%s (%s %s)", n.Name, n.Algorithm.String(), n.Type.String())
}

// List sends a "LIST" instruction, return a list of OATH credentials
func (o *OATH) List() ([]*Name, error) {

	var names []*Name

	res, err := o.send(0x00, INST_LIST, 0x00, 0x00)

	if err != nil {
		return nil, err
	}

	for _, tv := range res {

		switch tv.tag {
		case TAG_NAME_LIST:

			name := &Name{
				Algorithm: Algorithm(tv.value[0] & MASK_ALGO),
				Name:      string(tv.value[1:]),
				Type:      Type(tv.value[0] & MASK_TYPE),
			}

			names = append(names, name)

		default:
			return nil, fmt.Errorf(errUnknownTag, tv.tag)
		}

	}

	return names, nil

}
