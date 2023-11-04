// SPDX-FileCopyrightText: 2023 Steffen Vogel <post@steffenvogel.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	iso "cunicu.li/go-iso7816"
)

type Error iso.Code

var (
	ErrAuthRequired         = Error{0x69, 0x82}
	ErrGeneric              = Error{0x65, 0x81}
	ErrNoSpace              = Error{0x6a, 0x84}
	ErrNoSuchObject         = Error{0x69, 0x84}
	ErrResponseDoesNotMatch = Error{0x69, 0x84}
	ErrWrongSyntax          = Error{0x6a, 0x80}
)

// Error return the encapsulated error string
func (e Error) Error() string {
	switch e {
	case ErrAuthRequired:
		return "authentication required"

	case ErrGeneric:
		return "generic error"

	case ErrNoSpace:
		return "no space"

	case ErrNoSuchObject:
		return "no such object"

	case ErrResponseDoesNotMatch:
		return "response does not match"

	case ErrWrongSyntax:
		return "wrong syntax"

	default:
		c := iso.Code(e)
		return c.Error()
	}
}

// IsMore indicates more data that needs to be fetched
func (e Error) HasMore() bool {
	return iso.Code(e).HasMore()
}

func wrapError(err error) error {
	if err, ok := err.(iso.Code); ok { //nolint:errorlint
		return Error(err)
	}

	return err
}
