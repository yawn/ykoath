// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

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
	res, err := o.send(0x00, insSelect, 0x04, 0x00,
		[]byte{0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01},
	)
	if err != nil {
		return nil, err
	}

	s := new(Select)

	for _, tv := range res {
		switch tv.tag {
		case tagAlgorithm:
			s.Algorithm = tv.value

		case tagChallenge:
			s.Challenge = tv.value

		case tagName:
			s.Name = tv.value

		case tagVersion:
			s.Version = tv.value

		default:
			return nil, fmt.Errorf("%w (%#x)", errUnknownTag, tv.tag)
		}
	}

	return s, nil
}
