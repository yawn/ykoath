// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath/v2"
)

func TestDelete(t *testing.T) {
	vs := vectorsTOTP[:1]
	withCard(t, vs, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		err := card.Delete(vs[0].Name)
		require.NoError(err)

		creds, err := card.List()
		require.NoError(err)
		require.Len(creds, 0)
	})
}
