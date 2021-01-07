# ykoath

[![Documentation](https://godoc.org/github.com/yawn/ykoath?status.svg)](http://godoc.org/github.com/yawn/ykoath) [![Go Report Card](https://goreportcard.com/badge/github.com/yawn/ykoath)](https://goreportcard.com/report/github.com/yawn/ykoath) [![Build Status](https://travis-ci.org/yawn/ykoath.svg?branch=master)](https://travis-ci.org/yawn/ykoath) [![Build status windows](https://ci.appveyor.com/api/projects/status/50vxo9e5jqql3y2b?svg=true)](https://ci.appveyor.com/project/yawn/ykoath)

The package `ykoath` implements the Yubikey [YOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html) over USB with the following exceptions:

* No support for HOTP (only TOTP)
* No support for `SET CODE` and subsequently no support for `VALIDATE` and `SELECT` challenges - no authentication schema except requiring touch is supported
* No support for `RESET` (removing all state from device)

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

## Authenticated example

If your Yubikey has a password, the above example will fail with an authentication required error. To authenticate, you will need to make a `Validate` call before any method that requires authentication. (Eg. `List()` or `Calculate()`). You can also determine if validation is required by checking the value of `Select.Challenge`.

Here is a partial example:
```
// Make select call
select, err = oath.Select()
if err != nil {
    logger.Fatal(err)
}

// If required, authenticate with password
if select.Challenge != nil {
    password := getYourUserPasswordFromSomewhere()
 	passKey := select.DeriveKey(string(bytePassword))
    ok, err := oath.Validate(select, passKey)
    if err != nil {
        logger.Fatal(err)
    }
    if !ok {
        logger.Fatal("failed validation, password is incorrect")
    }
}

// Now you can call other functions
names, err := oath.List()

```
