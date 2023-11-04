// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath"
)

func TestPIN(t *testing.T) {
	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		// Validate should fail if not PIN is set
		err := card.Validate([]byte("1234"))
		require.ErrorIs(err, ykoath.ErrNoSuchObject)

		// Select applet again
		sel, err := card.Select()
		require.NoError(err)
		require.Nil(sel.Challenge)
		require.Nil(sel.Algorithm)

		// Set PIN
		err = card.SetCode([]byte("1338"), ykoath.HmacSha256)
		require.NoError(err)

		// Reset card to clear authenticated state
		// err = test.ResetCard(card.Card)
		// require.NoError(err)

		// Select applet again
		sel, err = card.Select()
		require.NoError(err)

		require.NotNil(sel.Challenge)
		require.Len(sel.Algorithm, 1)
		require.Equal(ykoath.Algorithm(sel.Algorithm[0]), ykoath.HmacSha256)

		// RemoveCode should fail as we are not authenticated yet
		// err = card.RemoveCode()
		// require.ErrorIs(err, ykoath.ErrAuthRequired)

		// Test invalid PIN
		err = card.Validate([]byte("1337"))
		require.ErrorIs(err, ykoath.ErrWrongSyntax)

		// Test valid PIN
		err = card.Validate([]byte("1338"))
		require.NoError(err)

		// RemoveCode should succeed now
		err = card.RemoveCode()
		require.NoError(err)
	})
}
