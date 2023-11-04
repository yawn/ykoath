// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"math/rand"
	"testing"
	"time"

	iso "cunicu.li/go-iso7816"
	yk "cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/test"
	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath"
)

// withCard is a helper to initialize a card for testing
func withCard(t *testing.T, vs []vector, cb func(t *testing.T, card *ykoath.Card)) {
	test.WithCard(t, yk.HasOATH, func(t *testing.T, isoCard *iso.Card) {
		require := require.New(t)

		oathCard, err := ykoath.NewCard(isoCard)
		require.NoError(err)

		_, err = oathCard.Select()
		require.NoError(err, "Failed to select applet")

		err = oathCard.Reset()
		require.NoError(err, "Failed to reset applet")

		for _, v := range vs {
			v := v
			err = oathCard.Put(v.Name, v.Alg, v.Typ, v.Digits, v.Secret, v.Touch, v.Counter)
			require.NoError(err, "Failed to put credential")
		}

		// Fix the clock for our tests
		oathCard.Clock = func() time.Time {
			return time.Unix(59, 0)
		}

		// Fix the random source for reproducible tests
		oathCard.Rand = rand.New(rand.NewSource(4242)) //nolint:gosec

		cb(t, oathCard)

		err = oathCard.Close()
		require.NoError(err)
	})
}
