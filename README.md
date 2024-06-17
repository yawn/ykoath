# ykoath

[![Documentation](https://godoc.org/github.com/yawn/ykoath?status.svg)](http://godoc.org/github.com/yawn/ykoath) [![Go Report Card](https://goreportcard.com/badge/github.com/yawn/ykoath)](https://goreportcard.com/report/github.com/yawn/ykoath) [![Build Status](https://github.com/yawn/ykoath/actions/workflows/ci.yml/badge.svg)](https://github.com/yawn/ykoath/actions/workflows/ci.yml)


The package `ykoath` implements the Yubikey [YOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html) over USB with the following exceptions:

* No support for HOTP (only TOTP)
* No support for `SET CODE` and subsequently no support for `VALIDATE` and `SELECT` challenges - no authentication schema except requiring touch is supported
* No support for `RESET` (removing all state from device)

`ykoath` is primarily maintained by [Les Aker](https://github.com/akerl) these days. Thanks a lot for your support!

## Example usage

```

logger := log.New(os.Stderr, "", log.LstdFlags)

oath, err := ykoath.New()

if err != nil {
	log.Fatal(err)
}

oath.Debug = logger

defer oath.Close()

_, err = oath.Select()

if err != nil {
	logger.Fatal(errors.Wrapf(err, "failed to select"))
}

names, err := oath.List()

if err != nil {
	logger.Fatal(errors.Wrapf(err, "failed to list"))
}

for _, name := range names {

	calc, err := oath.Calculate(name.Name, func(name string) error {
		fmt.Printf("*** PLEASE TOUCH YOUR YUBIKEY TO UNLOCK %q ***\n", name)
		return nil
	})

	if err != nil {
		logger.Fatal(errors.Wrapf(err, "failed to calculate name for %q", name.Name))
	}

	fmt.Printf("Got one-time-password %s for %q\n", calc, name)

}

if err := oath.Put("test", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
	logger.Fatal(err)
}

if err := oath.Put("test2", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
	logger.Fatal(err)
}

```
