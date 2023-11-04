// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"fmt"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

// Select encapsulates the results of the "SELECT" instruction
type Select struct {
	Algorithm []byte
	Challenge []byte
	Name      []byte
	Version   []byte
}

func (s *Select) UnmarshalBinary(b []byte) error {
	tvs, err := tlv.DecodeSimple(b)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	for _, tv := range tvs {
		switch tv.Tag {
		case tagAlgorithm:
			s.Algorithm = tv.Value

		case tagChallenge:
			s.Challenge = tv.Value

		case tagName:
			s.Name = tv.Value

		case tagVersion:
			s.Version = tv.Value

		default:
			return fmt.Errorf("%w (%#x)", errUnknownTag, tv.Tag)
		}
	}

	return nil
}

// Select sends a "SELECT" instruction, initializing the device for an OATH session
func (c *Card) Select() (*Select, error) {
	resp, err := c.Card.Select(iso.AidYubicoOATH)
	if err != nil {
		return nil, wrapError(err)
	}

	s := &Select{}
	return s, s.UnmarshalBinary(resp)
}
