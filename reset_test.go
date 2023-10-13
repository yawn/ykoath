// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReset(t *testing.T) {
	var (
		assert   = assert.New(t)
		testCard = new(testCard)
	)

	testCard.
		On(
			"Transmit",
			[]byte{
				0x00, 0x04, 0xde, 0xad,
			}).
		Return(
			[]byte{
				0x90, 0x00,
			},
			nil,
		).Once()

	client := &OATH{
		Timestep: DefaultTimeStep,
		card:     testCard,
	}

	err := client.Reset()
	assert.NoError(err)

	testCard.AssertExpectations(t)
}
