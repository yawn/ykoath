// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"cunicu.li/go-iso7816/encoding/tlv"
)

// Delete sends a "DELETE" instruction, removing one named OATH credential
func (c *Card) Delete(name string) error {
	_, err := c.send(insDelete, 0x00, 0x00,
		tlv.New(tagName, []byte(name)),
	)
	return err
}
