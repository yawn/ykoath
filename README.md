<!--
SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
SPDX-License-Identifier: Apache-2.0
-->

# go-ykoath

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/cunicu/go-ykoath/test.yaml?style=flat-square)](https://github.com/cunicu/go-ykoath/actions)
[![goreportcard](https://goreportcard.com/badge/github.com/cunicu/go-ykoath?style=flat-square)](https://goreportcard.com/report/github.com/cunicu/go-ykoath)
[![Codecov branch](https://img.shields.io/codecov/c/github/cunicu/go-ykoath/main?style=flat-square&token=6XoWouQg6K)](https://app.codecov.io/gh/cunicu/go-ykoath/tree/main)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](https://github.com/cunicu/go-ykoath/blob/main/LICENSES/Apache-2.0.txt)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/cunicu/go-ykoath?style=flat-square)
[![Go Reference](https://pkg.go.dev/badge/github.com/cunicu/go-ykoath.svg)](https://pkg.go.dev/github.com/cunicu/go-ykoath)

The package `ykoath` implements the YubiKey [YKOATH protocol](https://developers.yubico.com/OATH/YKOATH_Protocol.html) over USB with the following exceptions:

* No support for HOTP (only TOTP)

## Usage

```go
c, err := ykoath.New()
if err != nil {
    log.Fatal(err)
}

defer c.Close()

if _, err = c.Select(); err != nil {
    log.Fatalf("Failed to select app: %v", err)
}

names, err := c.List()
if err != nil {
    log.Fatal("Failed to list slots: %v", err)
}

for _, name := range names {
    calc, err := c.Calculate(name.Name, func(name string) error {
        log.Printf("*** Please touch your YubiKey to unlock slot: %q ***", name)
        return nil
    })
    if err != nil {
        log.Fatal("Failed to calculate code for slot %q: %v", name.Name, err)
    }

    log.Printf("Got one-time-password %s for slot %q", calc, name)
}

if err := c.Put("test", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
    log.Fatal(err)
}

if err := c.Put("test2", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
    log.Fatal(err)
}
```

## Authors

go-ykoath has been forked from [yawn/ykoath](https://github.com/yawn/ykoath) at commit [201009e](https://github.com/yawn/ykoath/commit/201009e71bce473daf61858fe69990d8e4300975)

* Joern Barthel ([@yawn](https://github.com/yawn))
* Steffen Vogel ([@stv0g](https://github.com/stv0g))

## License

go-ykoath is licensed under the [Apache 2.0](./LICENSE) license.
