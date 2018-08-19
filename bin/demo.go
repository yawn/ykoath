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

	list, err := oath.List()

	if err != nil {
		log.Fatal(errors.Wrapf(err, "failed to list"))
	}

	for _, name := range list {

		calc, err := oath.Calculate(name)

		if err != nil {
			log.Fatal(errors.Wrapf(err, "failed to calculate name for %q", name))
		}

		fmt.Printf("%s\t%q\n", calc, name)

	}

}
