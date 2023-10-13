// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSelect(t *testing.T) {
	var (
		assert   = assert.New(t)
		testCard = new(testCard)
	)

	testCard.
		On(
			"Transmit",
			[]byte{
				0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01,
			}).
		Return(
			[]byte{
				0x79, 0x03, 0x04, 0x03, 0x03, 0x71, 0x08, 0x7c, 0x06, 0x60, 0x15, 0x20,
				0xfc, 0x3f, 0x8f, 0x90, 0x00,
			},
			nil,
		)

	client := &OATH{
		Timestep: DefaultTimeStep,
		card:     testCard,
	}

	res, err := client.Select()

	assert.Empty(res.Algorithm)
	assert.Empty(res.Challenge)
	assert.Equal(fmt.Sprintf("% x", []byte{0x7c, 0x06, 0x60, 0x15, 0x20, 0xfc, 0x3f, 0x8f}), fmt.Sprintf("% x", res.Name))
	assert.Equal(fmt.Sprintf("% x", []byte{0x04, 0x03, 0x03}), fmt.Sprintf("% x", res.Version))

	assert.NoError(err)

	testCard.AssertExpectations(t)
}
