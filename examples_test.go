// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

//go:build !ci

package ykoath_test

import (
	"fmt"
	"log"
	"time"

	yk "cunicu.li/go-iso7816/devices/yubikey"
	"cunicu.li/go-iso7816/drivers/pcsc"
	"github.com/ebfe/scard"

	"cunicu.li/go-ykoath/v2"
)

func Example() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		log.Printf("Failed to establish context: %v", err)
		return
	}

	sc, err := pcsc.OpenFirstCard(ctx, yk.HasOATH)
	if err != nil {
		log.Printf("Failed to connect to card: %v", err)
		return
	}

	c, err := ykoath.NewCard(sc)
	if err != nil {
		log.Print(err)
		return
	}

	defer c.Close()

	// Fix the clock
	c.Clock = func() time.Time {
		return time.Unix(59, 0)
	}

	// Enable OATH for this session
	if _, err = c.Select(); err != nil {
		log.Printf("Failed to select applet: %v", err)
		return
	}

	// Reset the applet
	// if err := c.Reset(); err != nil {
	// 	log.Printf("Failed to reset applet: %v", err)
	// 	return
	// }

	// Add the testvector
	if err = c.Put("testvector", ykoath.HmacSha1, ykoath.Totp, 8, []byte("12345678901234567890"), false, 0); err != nil {
		log.Printf("Failed to put: %v", err)
		return
	}

	names, err := c.List()
	if err != nil {
		log.Printf("Failed to list: %v", err)
		return
	}

	for _, name := range names {
		fmt.Printf("Name: %s\n", name)
	}

	otp, _ := c.CalculateMatch("testvector", nil)
	fmt.Printf("OTP: %s\n", otp)

	// Output:
	// Name: testvector (HMAC-SHA1 TOTP)
	// OTP: 94287082
}
