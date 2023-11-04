// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath/v2"
)

func TestReset(t *testing.T) {
	withCard(t, vectorsTOTP[:1], func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		err := card.Reset()
		require.NoError(err)

		creds, err := card.List()
		require.NoError(err)
		require.Len(creds, 0)
	})
}
