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
		log.Fatal(err)
	}

	defer oath.Close()

	// Fix the clock
	oath.Clock = func() time.Time {
		return time.Unix(59, 0)
	}

	// Enable OATH for this session
	if _, err = oath.Select(); err != nil {
		log.Fatalf("Failed to select app: %v", err)
	}

	// Add the testvector
	if err = oath.Put("testvector", HmacSha1, Totp, 8, []byte("12345678901234567890"), false); err != nil {
		log.Fatalf("Failed to put: %v", err)
	}

	names, err := oath.List()
	if err != nil {
		log.Fatalf("Failed to list: %v", err)
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
