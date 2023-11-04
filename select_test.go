// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"cunicu.li/go-ykoath"
)

func TestSelect(t *testing.T) {
	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
		assert := assert.New(t)

		res, err := card.Select()
		assert.NoError(err)

		assert.Empty(res.Algorithm)
		assert.Empty(res.Challenge)
		assert.Len(res.Name, 8) // Name gets regenerated during each applet reset
		assert.Equal([]byte{0x05, 0x04, 0x03}, res.Version)
	})
}
