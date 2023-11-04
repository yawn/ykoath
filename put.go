// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"encoding/binary"
	"errors"
	"fmt"

	"cunicu.li/go-iso7816/encoding/tlv"
)

var ErrNameTooLong = errors.New("name too long)")

// Put sends a "PUT" instruction, storing a new / overwriting an existing OATH
// credentials with an algorithm and type, 6 or 8 digits one-time password,
// shared secrets and touch-required bit
func (c *Card) Put(name string, alg Algorithm, typ Type, digits int, key []byte, touch bool, counter uint32) error {
	if l := len(name); l > 64 {
		return fmt.Errorf("%w: (%d > 64)", ErrNameTooLong, l)
	}

	key = shortenKey(key, alg)
	key = padKey(key)

	tvs := []tlv.TagValue{
		tlv.New(tagName, []byte(name)),
		tlv.New(tagKey, []byte{byte(alg) | byte(typ), byte(digits)}, key),
	}

	if touch {
		tvs = append(tvs, tlv.TagValue{
			Tag:        tagProperty,
			Value:      []byte{0x02},
			SkipLength: true,
		})
	}

	if counter > 0 {
		tvs = append(tvs, tlv.TagValue{
			Tag:   tagImf,
			Value: binary.BigEndian.AppendUint32(nil, counter),
		})
	}

	_, err := c.send(insPut, 0x00, 0x00, tvs...)
	return err
}

func shortenKey(key []byte, alg Algorithm) []byte {
	if h := alg.Hash()(); len(key) > h.BlockSize() {
		h.Write(key)
		return h.Sum(nil)
	}

	return key
}

func padKey(key []byte) []byte {
	keyLen := len(key)
	if keyLen >= HMACMinimumKeySize {
		return key
	}

	pad := make([]byte, HMACMinimumKeySize-keyLen)

	return append(pad, key...)
}
