// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCredential(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		Data     []byte
		Type     Type
		Expected credential
	}{
		{
			Data: []byte("test"),
			Type: Totp,
			Expected: credential{
				Issuer:   "",
				Name:     "test",
				TimeStep: DefaultTimeStep,
			},
		},
		{
			Data: []byte("testIssuer:testName"),
			Type: Totp,
			Expected: credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: DefaultTimeStep,
			},
		},
		{
			Data: []byte("45/testIssuer:testName"),
			Type: Totp,
			Expected: credential{
				Issuer:   "testIssuer",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
		{
			Data: []byte("45/testName"),
			Type: Totp,
			Expected: credential{
				Issuer:   "",
				Name:     "testName",
				TimeStep: 45 * time.Second,
			},
		},
	}

	for _, tc := range cases {
		var cred credential

		err := cred.Unmarshal(tc.Data, tc.Type)
		assert.NoError(err)

		assert.Equal(tc.Expected, cred)

		data := cred.Marshal()
		assert.Equal(tc.Data, data, "Got: %s", string(data))
	}
}
