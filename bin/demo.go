package main

import (
	"fmt"
	"log"

	"github.com/pkg/errors"
	"github.com/yawn/ykoath"
)

func main() {

	// TODO: implement retries

	oath, err := ykoath.New()

	if err != nil {
		log.Fatal(err)
	}

	defer oath.Close()

	_, err = oath.Select()

	if err != nil {
		log.Fatal(errors.Wrapf(err, "failed to select"))
	}

	names, err := oath.List()

	if err != nil {
		log.Fatal(errors.Wrapf(err, "failed to list"))
	}

	log.Println(names)

	for _, name := range names {

		calc, err := oath.Calculate(name.Name)

		if err != nil {
			log.Fatal(errors.Wrapf(err, "failed to calculate name for %q", name.Name))
		}

		fmt.Printf("%s\t%q\n", calc, name)

	}

	if err := oath.Put("test", ykoath.HmacSha1, ykoath.Totp, 6, []byte("open sesame"), true); err != nil {
		log.Fatal(err)
	}

}
