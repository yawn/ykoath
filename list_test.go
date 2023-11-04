// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath"
)

func TestList(t *testing.T) {
	vs := vectorsTOTP[:3]
	withCard(t, vs, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		res, err := card.List()
		require.NoError(err)
		require.Len(res, len(vs))

		vm := map[string]*vector{}
		for _, v := range vs {
			v := v
			vm[v.Name] = &v
		}

		for _, r := range res {
			vector, ok := vm[r.Name]
			require.True(ok)

			require.Equal(vector.Alg, r.Algorithm)
			require.Equal(vector.Name, r.Name)
			require.Equal(vector.Typ, r.Type)
		}
	})
}
