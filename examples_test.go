// +build !ci

package ykoath

import (
	"fmt"
	"time"
)

func Example() {

	oath, _ := New()

	// fix the clock
	oath.clock = func() time.Time {
		return time.Unix(59, 0)
	}

	defer oath.Close()

	// enable OATH for this session
	_, _ = oath.Select()

	// add the testvector
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
