package main

import (
	"fmt"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/yawn/ykoath"
)

func main() {

	// TODO: implement retries

	logger := log.New(os.Stderr, "", log.LstdFlags)

	oath, err := ykoath.New()

	if err != nil {
		log.Fatal(err)
	}

	//	oath.Debug = logger

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

		fmt.Printf("%s\t%q\n", calc, name)

	}

	if err := oath.Put("test", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
		logger.Fatal(err)
	}

	if err := oath.Put("test2", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
		logger.Fatal(err)
	}

}
