// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

// Reset resets the application to just-installed state.
// This command requires no authentication.
func (o *OATH) Reset() error {
	_, err := o.send(0x00, insReset, 0xde, 0xad)
	return err
}
