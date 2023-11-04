// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"cunicu.li/go-ykoath/v2"
)

func TestCalculate(t *testing.T) {
	vs := vectorsTOTP[:3]
	vs = append(vs, vectorsTOTP[:3]...)

	withCard(t, vs, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		for _, v := range vs {
			code, err := card.Calculate(v.Name, nil)
			require.NoError(err)
			require.Equal(v.Code, code)
		}
	})
}

func TestCalculateMatchPartial(t *testing.T) {
	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		err := card.Put("testvector", ykoath.HmacSha1, ykoath.Totp, 8, testSecretSHA1, false, 0)
		require.NoError(err)

		res, err := card.Calculate("test", nil)
		require.NoError(err)
		require.Equal("94287082", res)
	})
}

func TestCalculateMatchFull(t *testing.T) {
	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		err := card.Put("testvector", ykoath.HmacSha1, ykoath.Totp, 8, testSecretSHA1, false, 0)
		require.NoError(err)

		res, err := card.Calculate("testvector", nil)
		require.NoError(err)
		require.Equal("94287082", res)
	})
}

func TestCalculateMatchMultiple(t *testing.T) {
	withCard(t, nil, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		err := card.Put("testvector1", ykoath.HmacSha1, ykoath.Totp, 8, testSecretSHA1, false, 0)
		require.NoError(err)

		err = card.Put("testvector2", ykoath.HmacSha1, ykoath.Totp, 8, testSecretSHA1, false, 0)
		require.NoError(err)

		_, err = card.Calculate("test", nil)
		require.ErrorIs(err, ykoath.ErrMultipleMatches)
	})
}

func TestCalculateRequireTouch(t *testing.T) {
	withCard(t, []vector{
		{
			Name:   "touch required",
			Alg:    ykoath.HmacSha256,
			Typ:    ykoath.Totp,
			Digits: 6,
			Secret: fromHex("12341234"),
			Touch:  true,
		},
	}, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		// Callback missing
		_, err := card.Calculate("touch", nil)
		require.ErrorIs(err, ykoath.ErrTouchCallbackRequired)

		// Error raised in callback
		_, err = card.Calculate("touch", func(s string) error {
			return errors.New("my error") //nolint:goerr113
		})
		require.ErrorContains(err, "my error")

		// Callback called but button not pressed
		touchRequested := false
		_, err = card.Calculate("touch", func(s string) error {
			require.Equal(s, "touch required")
			touchRequested = true
			return nil
		})
		require.NoError(err)
		require.True(touchRequested)
	})
}

func TestCalculateTOTP(t *testing.T) {
	v := vectorsTOTP[0]
	withCard(t, []vector{v}, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		code, err := card.CalculateDirect(v.Name)
		require.NoError(err)
		require.Equal(v.Code, code)
	})
}

func TestCalculateHOTPCounterIncrement(t *testing.T) {
	v := vectorsHOTP[0]
	withCard(t, []vector{v}, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		for _, ev := range vectorsHOTP[:10] {
			code, err := card.CalculateDirect(v.Name)
			require.NoError(err)
			require.Equal(ev.Code, code)
		}
	})
}

func TestCalculateHOTPCounterInit(t *testing.T) {
	withCard(t, vectorsHOTP, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		for _, v := range vectorsHOTP {
			code, err := card.CalculateDirect(v.Name)
			require.NoError(err)
			require.Equal(v.Code, code)
		}
	})
}

func TestCalculateRAW(t *testing.T) {
	expResp := fromHex("28c6d33a03e7c67940c30d06253f8980f8ef54bd")

	v := vectorsTOTP[0]
	withCard(t, []vector{v}, func(t *testing.T, card *ykoath.Card) {
		require := require.New(t)

		resp, _, err := card.CalculateRaw(v.Name, fromString("hallo"))
		require.NoError(err)
		require.Equal(expResp, resp)
		require.Len(resp, v.Alg.Hash()().Size())
	})
}
