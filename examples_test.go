// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !ci

package ykoath

import (
	"fmt"
	"log"
	"time"
)

func Example() {
	oath, err := New()
	if err != nil {
		log.Print(err)
		return
	}

	defer oath.Close()

	// Fix the clock
	oath.Clock = func() time.Time {
		return time.Unix(59, 0)
	}

	// Enable OATH for this session
	if _, err = oath.Select(); err != nil {
		log.Printf("Failed to select app: %v", err)
		return
	}

	// Add the testvector
	if err = oath.Put("testvector", HmacSha1, Totp, 8, []byte("12345678901234567890"), false); err != nil {
		log.Printf("Failed to put: %v", err)
		return
	}

	names, err := oath.List()
	if err != nil {
		log.Printf("Failed to list: %v", err)
		return
	}

	for _, name := range names {
		fmt.Printf("Name: %s\n", name)
	}

	otp, _ := oath.Calculate("testvector", nil)
	fmt.Printf("OTP: %s\n", otp)

	// Output:
	// Name: testvector (HMAC-SHA1 TOTP)
	// OTP: 94287082
}
