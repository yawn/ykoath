// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !ci

package ykoath

import (
	"fmt"
	"time"
)

func Example() {
	oath, _ := New()

	// Fix the clock
	oath.Clock = func() time.Time {
		return time.Unix(59, 0)
	}

	defer oath.Close()

	// Enable OATH for this session
	_, _ = oath.Select()

	// Add the testvector
	_ = oath.Put("testvector", HmacSha1, Totp, 8, []byte("12345678901234567890"), false)

	names, _ := oath.List()

	for _, name := range names {
		fmt.Println(name)
	}

	otp, _ := oath.Calculate("testvector", nil)
	fmt.Println(otp)

	// Output:
	// testvector (HMAC-SHA1 TOTP)
	// 94287082
}
