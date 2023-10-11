// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !ci

package ykoath

import (
	"flag"
	"testing"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/require"
)

// canResetYubikey indicates whether the test running has constented to
// destroying data on YubiKeys connected to the system.
var canResetYubikey = flag.Bool("reset-yubikey", false,
	"Flag required to run tests that access the yubikey")

func TestPIN(t *testing.T) {
	require := require.New(t)

	if !*canResetYubikey {
		t.Skip("not running test that accesses yubikey, provide --wipe-yubikey flag")
	}

	oath, err := New()
	require.NoError(err)

	defer oath.Close()

	// Reset token to factory state
	_, err = oath.Select()
	require.NoError(err)

	err = oath.Reset()
	require.NoError(err)

	// Validate should fail if not PIN is set
	err = oath.Validate([]byte("1234"))
	require.ErrorIs(err, errNoSuchObject)

	// Select applet again
	sel, err := oath.Select()
	require.NoError(err)
	require.Nil(sel.Challenge)
	require.Nil(sel.Algorithm)

	// Set PIN
	err = oath.SetCode([]byte("1338"), HmacSha256)
	require.NoError(err)

	// Reset card to clear authenticated state
	card, ok := oath.card.(*scard.Card)
	require.True(ok)

	err = card.Reconnect(scard.ShareShared, scard.ProtocolT1, scard.ResetCard)
	require.NoError(err)

	// Select applet again
	sel, err = oath.Select()
	require.NoError(err)
	require.NotNil(sel.Challenge)
	require.Len(sel.Algorithm, 1)
	require.Equal(Algorithm(sel.Algorithm[0]), HmacSha256)

	// RemoveCode should fail as we are not authenticated yet
	err = oath.RemoveCode()
	require.ErrorIs(err, errAuthRequired)

	// Test invalid PIN
	err = oath.Validate([]byte("1337"))
	require.ErrorIs(err, errWrongSyntax)

	// Test valid PIN
	err = oath.Validate([]byte("1338"))
	require.NoError(err)

	// RemoveCode should succeed now
	err = oath.RemoveCode()
	require.NoError(err)
}
