// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

// Delete sends a "DELETE" instruction, removing one named OATH credential
func (o *OATH) Delete(name string) error {
	_, err := o.send(0x00, 0x02, 0x00, 0x00,
		write(0x71, []byte(name)))

	return err
}
