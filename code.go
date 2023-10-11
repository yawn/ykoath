// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"fmt"
)

// code encapsulates (some) response codes from the spec
type code [2]byte

var (
	errSuccess              = code{0x90, 0x00}
	errAuthRequired         = code{0x69, 0x82}
	errGeneric              = code{0x65, 0x81}
	errNoSpace              = code{0x6a, 0x84}
	errNoSuchObject         = code{0x69, 0x84}
	errResponseDoesNotMatch = code{0x69, 0x84}
	errWrongSyntax          = code{0x6a, 0x80}
)

// Error return the encapsulated error string
func (c code) Error() string {
	switch c {
	case errAuthRequired:
		return "authentication required"

	case errGeneric:
		return "generic error"

	case errNoSpace:
		return "no space"

	case errNoSuchObject:
		return "no such object"

	case errResponseDoesNotMatch:
		return "response does not match"

	case errWrongSyntax:
		return "wrong syntax"
	}

	return fmt.Sprintf("unknown (0x%x%x)", c[0], c[1])
}

// IsMore indicates more data that needs to be fetched
func (c code) IsMore() bool {
	return c[0] == 0x61
}
