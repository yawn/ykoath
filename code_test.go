// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath"
)

func TestOTP(t *testing.T) {
	require := require.New(t)
	for _, v := range vectors["HOTP"] {
		c := ykoath.Code{
			Hash:   v.Hash,
			Digits: v.Digits,
		}

		require.Equal(v.Code, c.OTP())
	}
}
