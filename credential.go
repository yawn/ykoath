// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var credRegex = regexp.MustCompile(`^((?P<timestep>\d+)/)?((?P<issuer>[^:]+):)?(?P<name>.+)$`)

type credential struct {
	TimeStep time.Duration
	Name     string
	Issuer   string
}

func (c credential) String() string {
	return fmt.Sprintf("%s: %s", c.Issuer, c.Name)
}

func (c credential) Marshal() []byte {
	s := ""

	if c.TimeStep != DefaultTimeStep {
		s += fmt.Sprintf("%d/", c.TimeStep/time.Second)
	}

	if c.Issuer != "" {
		s += c.Issuer + ":"
	}

	s += c.Name

	return []byte(s)
}

func (c *credential) Unmarshal(b []byte, t Type) error {
	s := string(b)

	if t == Hotp {
		if parts := strings.SplitN(s, ":", 2); len(parts) > 1 {
			c.Issuer = parts[0]
			c.Name = parts[1]
		} else {
			c.Issuer = ""
			c.Name = parts[0]
		}

		c.TimeStep = 0

		return nil
	}

	m := credRegex.FindStringSubmatch(s)
	if m != nil {
		if m[2] != "" {
			ts, err := strconv.Atoi(m[2])
			if err != nil {
				return err
			}

			c.TimeStep = time.Second * time.Duration(ts)
		} else {
			c.TimeStep = DefaultTimeStep
		}

		c.Issuer = m[4]
		c.Name = m[5]

		return nil
	}

	c.Issuer = ""
	c.Name = s
	c.TimeStep = DefaultTimeStep

	return nil
}
