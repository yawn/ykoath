// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	yk "cunicu.li/go-ykoath"
)

func TestCredential(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		Data     []byte
		Type     yk.Type
		Expected yk.Credential
	}{
		{
			Data: []byte("test"),
			Type: yk.Totp,
			Expected: yk.Credential{
				Issuer:   "",
				Name:     "test",
				TimeStep: yk.DefaultTimeStep,
			},
		},
		{
			Data: []byte("testIssuer:testName"),
			Type: yk.Totp,
			Expected: yk.Credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: yk.DefaultTimeStep,
			},
		},
		{
			Data: []byte("45/testIssuer:testName"),
			Type: yk.Totp,
			Expected: yk.Credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
		{
			Data: []byte("45/testName"),
			Type: yk.Totp,
			Expected: yk.Credential{
				Issuer:   "",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
	}

	for _, tc := range cases {
		var cred yk.Credential

		err := cred.Unmarshal(tc.Data, tc.Type)
		assert.NoError(err)

		assert.Equal(tc.Expected, cred)

		data := cred.Marshal()
		assert.Equal(tc.Data, data, "Got: %s", string(data))
	}
}
