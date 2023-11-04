// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"cunicu.li/go-ykoath/v2"
)

func TestCredential(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		Data     []byte
		Type     ykoath.Type
		Expected ykoath.Credential
	}{
		{
			Data: []byte("test"),
			Type: ykoath.Totp,
			Expected: ykoath.Credential{
				Issuer:   "",
				Name:     "test",
				TimeStep: ykoath.DefaultTimeStep,
			},
		},
		{
			Data: []byte("testIssuer:testName"),
			Type: ykoath.Totp,
			Expected: ykoath.Credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: ykoath.DefaultTimeStep,
			},
		},
		{
			Data: []byte("45/testIssuer:testName"),
			Type: ykoath.Totp,
			Expected: ykoath.Credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
		{
			Data: []byte("45/testName"),
			Type: ykoath.Totp,
			Expected: ykoath.Credential{
				Issuer:   "",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
	}

	for _, tc := range cases {
		var cred ykoath.Credential

		err := cred.Unmarshal(tc.Data, tc.Type)
		assert.NoError(err)

		assert.Equal(tc.Expected, cred)

		data := cred.Marshal()
		assert.Equal(tc.Data, data, "Got: %s", string(data))
	}
}
