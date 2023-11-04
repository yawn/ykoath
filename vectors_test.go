// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath_test

import (
	"encoding/hex"
	"time"

	"cunicu.li/go-ykoath"
)

type vector struct {
	Alg     ykoath.Algorithm
	Digits  int
	Secret  []byte
	Name    string
	Typ     ykoath.Type
	Time    time.Time
	Counter uint32
	Code    string
	Hash    []byte
	Touch   bool
}

func fromString(s string) []byte {
	return []byte(s)
}

func fromHex(s string) []byte {
	h, err := hex.DecodeString(s)
	if err != nil {
		panic("failed to parse hex: " + err.Error())
	}
	return h
}

var (
	// See: https://www.rfc-editor.org/errata/eid2866
	testSecretSHA1   = fromString("12345678901234567890")
	testSecretSHA256 = fromString("12345678901234567890123456789012")
	testSecretSHA512 = fromString("1234567890123456789012345678901234567890123456789012345678901234")

	vectorsTOTP = []vector{
		// RFC 6238 Appendix B - Test Vectors
		// See: https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
		{Name: "rfc6238-test-01", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(59, 0), Code: "94287082"},
		{Name: "rfc6238-test-02", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(59, 0), Code: "46119246"},
		{Name: "rfc6238-test-03", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(59, 0), Code: "90693936"},
		{Name: "rfc6238-test-04", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1111111109, 0), Code: "07081804"},
		{Name: "rfc6238-test-05", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1111111109, 0), Code: "68084774"},
		{Name: "rfc6238-test-06", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1111111109, 0), Code: "25091201"},
		{Name: "rfc6238-test-07", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1111111111, 0), Code: "14050471"},
		{Name: "rfc6238-test-08", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1111111111, 0), Code: "67062674"},
		{Name: "rfc6238-test-09", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1111111111, 0), Code: "99943326"},
		{Name: "rfc6238-test-10", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(1234567890, 0), Code: "89005924"},
		{Name: "rfc6238-test-11", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(1234567890, 0), Code: "91819424"},
		{Name: "rfc6238-test-12", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(1234567890, 0), Code: "93441116"},
		{Name: "rfc6238-test-13", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(2000000000, 0), Code: "69279037"},
		{Name: "rfc6238-test-14", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(2000000000, 0), Code: "90698825"},
		{Name: "rfc6238-test-15", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(2000000000, 0), Code: "38618901"},
		{Name: "rfc6238-test-16", Alg: ykoath.HmacSha1, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA1, Time: time.Unix(20000000000, 0), Code: "65353130"},
		{Name: "rfc6238-test-17", Alg: ykoath.HmacSha256, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA256, Time: time.Unix(20000000000, 0), Code: "77737706"},
		{Name: "rfc6238-test-18", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 8, Secret: testSecretSHA512, Time: time.Unix(20000000000, 0), Code: "47863826"},

		{Name: "rfc6238-6digits-test-18", Alg: ykoath.HmacSha512, Typ: ykoath.Totp, Digits: 6, Secret: testSecretSHA512, Time: time.Unix(20000000000, 0), Code: "863826"},
	}

	vectorsHOTP = []vector{
		// RFC 4226 Appendix D - HOTP Algorithm: Test Values
		// See: https://datatracker.ietf.org/doc/html/rfc4226#page-32
		{Name: "rfc4226-test-00", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 0, Code: "755224", Hash: fromHex("cc93cf18508d94934c64b65d8ba7667fb7cde4b0")},
		{Name: "rfc4226-test-01", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 1, Code: "287082", Hash: fromHex("75a48a19d4cbe100644e8ac1397eea747a2d33ab")},
		{Name: "rfc4226-test-02", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 2, Code: "359152", Hash: fromHex("0bacb7fa082fef30782211938bc1c5e70416ff44")},
		{Name: "rfc4226-test-03", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 3, Code: "969429", Hash: fromHex("66c28227d03a2d5529262ff016a1e6ef76557ece")},
		{Name: "rfc4226-test-04", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 4, Code: "338314", Hash: fromHex("a904c900a64b35909874b33e61c5938a8e15ed1c")},
		{Name: "rfc4226-test-05", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 5, Code: "254676", Hash: fromHex("a37e783d7b7233c083d4f62926c7a25f238d0316")},
		{Name: "rfc4226-test-06", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 6, Code: "287922", Hash: fromHex("bc9cd28561042c83f219324d3c607256c03272ae")},
		{Name: "rfc4226-test-07", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 7, Code: "162583", Hash: fromHex("a4fb960c0bc06e1eabb804e5b397cdc4b45596fa")},
		{Name: "rfc4226-test-08", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 8, Code: "399871", Hash: fromHex("1b3c89f65e6c9e883012052823443f048b4332db")},
		{Name: "rfc4226-test-09", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 6, Secret: testSecretSHA1, Counter: 9, Code: "520489", Hash: fromHex("1637409809a679dc698207310c8c7fc07290d9e5")},

		{Name: "rfc4226-8digits-test-09", Alg: ykoath.HmacSha1, Typ: ykoath.Hotp, Digits: 8, Secret: testSecretSHA1, Counter: 9, Code: "45520489", Hash: fromHex("1637409809a679dc698207310c8c7fc07290d9e5")},
	}

	vectors = map[string][]vector{
		"TOTP": vectorsTOTP,
		"HOTP": vectorsHOTP,
	}
)
