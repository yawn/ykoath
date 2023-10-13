// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"sort"

	"github.com/ebfe/scard"
	"github.com/stretchr/testify/mock"
)

type testCard struct {
	mock.Mock
}

func (t *testCard) Disconnect(d scard.Disposition) error {
	args := t.Called(d)
	return args.Error(0)
}

func (t *testCard) Transmit(b []byte) ([]byte, error) {
	args := t.Called(b)
	return args.Get(0).([]byte), args.Error(1) //nolint:forcetypeassert
}

type vector struct {
	a          Algorithm
	digits     uint8
	key        []byte
	name       string
	t          Type
	testvector string
	time       int64
	touch      bool
}

var (
	keys    sort.StringSlice
	vectors map[string]*vector
)

func init() { //nolint:gochecknoinits
	vectors = map[string]*vector{
		"test-01-1e5f2db9-477e-41af-bd2e-60bc569ae871": {
			a:          HmacSha1,
			t:          Totp,
			digits:     6,
			key:        []byte("12345678901234567890"),
			touch:      false,
			time:       59,
			testvector: "287082",
		},
		"test-02-2a7cbca9-baef-47e3-8ce8-788bc6853e12": {
			a:          HmacSha256,
			t:          Totp,
			digits:     6,
			key:        []byte("12345678901234567890123456789012"),
			touch:      true,
			time:       59,
			testvector: "119246",
		},
		"test-03-b01019ed-2af1-48cc-a64c-fa9b424db993": {
			a:          HmacSha512,
			t:          Totp,
			digits:     6,
			key:        []byte("1234567890123456789012345678901234567890123456789012345678901234"),
			touch:      false,
			time:       59,
			testvector: "693936",
		},
		"test-04-e62171f0-4cf6-499e-b988-6ef36b213cc6": {
			a:          HmacSha1,
			t:          Totp,
			digits:     6,
			key:        []byte("12345678901234567890"),
			touch:      true,
			time:       59,
			testvector: "287082",
		},
		"test-05-458af9ee-caaa-4716-bfb8-bd828757955d": {
			a:          HmacSha256,
			t:          Totp,
			digits:     6,
			key:        []byte("12345678901234567890123456789012"),
			touch:      false,
			time:       59,
			testvector: "119246",
		},
		"test-06-2138a991-ec70-48cb-83e6-f80da47c93e4": {
			a:          HmacSha512,
			t:          Totp,
			digits:     6,
			key:        []byte("1234567890123456789012345678901234567890123456789012345678901234"),
			touch:      true,
			time:       59,
			testvector: "693936",
		},
		"test-07-a70a2520-7e51-45b2-baab-0e35220b06fe": {
			a:          HmacSha1,
			t:          Totp,
			digits:     8,
			key:        []byte("12345678901234567890"),
			touch:      false,
			time:       59,
			testvector: "94287082",
		},
		"test-08-83fe3208-b192-46c2-9cb2-14ee917b4d60": {
			a:          HmacSha256,
			t:          Totp,
			digits:     8,
			key:        []byte("12345678901234567890123456789012"),
			touch:      true,
			time:       59,
			testvector: "46119246",
		},
		"test-09-cc9d122e-9b51-435e-b48e-ab1a17157e3c": {
			a:          HmacSha512,
			t:          Totp,
			digits:     8,
			key:        []byte("1234567890123456789012345678901234567890123456789012345678901234"),
			touch:      false,
			time:       59,
			testvector: "90693936",
		},
		"test-10-97a58938-8ea6-4143-ae10-8adb92bdc335": {
			a:          HmacSha1,
			t:          Totp,
			digits:     8,
			key:        []byte("12345678901234567890"),
			touch:      true,
			time:       59,
			testvector: "94287082",
		},
		"test-11-887fd38b-80b3-4d7a-8671-82bef63151a6": {
			a:          HmacSha256,
			t:          Totp,
			digits:     8,
			key:        []byte("12345678901234567890123456789012"),
			touch:      false,
			time:       59,
			testvector: "46119246",
		},
		"test-12-daee50d1-7bbf-41e6-a65b-d34046dba287": {
			a:          HmacSha512,
			t:          Totp,
			digits:     8,
			key:        []byte("1234567890123456789012345678901234567890123456789012345678901234"),
			touch:      true,
			time:       59,
			testvector: "90693936",
		},
	}

	for k, v := range vectors {
		keys = append(keys, k)
		v.name = k
	}

	keys.Sort()
}
