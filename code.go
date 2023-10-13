// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"fmt"
)

// code encapsulates (some) response codes from the spec
type code [2]byte

var (
	errAuthRequired         = code{0x69, 0x82}
	errGeneric              = code{0x65, 0x81}
	errNoSpace              = code{0x6a, 0x84}
	errNoSuchObject         = code{0x69, 0x84}
	errResponseDoesNotMatch = code{0x69, 0x84}
	errWrongSyntax          = code{0x6a, 0x80}

	// Error codes from Nitrokeys Trussed Secrets App
	// See: https://github.com/Nitrokey/pynitrokey/blob/abf42efeff7794ebc29de281c93b14003c475407/pynitrokey/nk3/secrets_app.py#L133C6-L133C6
	errMoreDataAvailable                      = code{0x61, 0xFF}
	errVerificationFailed                     = code{0x63, 0x00}
	errUnspecifiedNonpersistentExecutionError = code{0x64, 0x00}
	errUnspecifiedPersistentExecutionError    = code{0x65, 0x00}
	errWrongLength                            = code{0x67, 0x00}
	errLogicalChannelNotSupported             = code{0x68, 0x81}
	errSecureMessagingNotSupported            = code{0x68, 0x82}
	errCommandChainingNotSupported            = code{0x68, 0x84}
	errSecurityStatusNotSatisfied             = code{0x69, 0x82}
	errConditionsOfUseNotSatisfied            = code{0x69, 0x85}
	errOperationBlocked                       = code{0x69, 0x83}
	errIncorrectDataParameter                 = code{0x6A, 0x80}
	errFunctionNotSupported                   = code{0x6A, 0x81}
	errNotFound                               = code{0x6A, 0x82}
	errNotEnoughMemory                        = code{0x6A, 0x84}
	errIncorrectP1OrP2Parameter               = code{0x6A, 0x86}
	errKeyReferenceNotFound                   = code{0x6A, 0x88}
	errInstructionNotSupportedOrInvalid       = code{0x6D, 0x00}
	errClassNotSupported                      = code{0x6E, 0x00}
	errUnspecifiedCheckingError               = code{0x6F, 0x00}
	errSuccess                                = code{0x90, 0x00}
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

	case errMoreDataAvailable:
		return "more data available"

	case errVerificationFailed:
		return "verification failed"

	case errUnspecifiedNonpersistentExecutionError:
		return "unspecified non-persistent execution error"

	case errUnspecifiedPersistentExecutionError:
		return "unspecified persistent execution error"

	case errWrongLength:
		return "wrong length"

	case errLogicalChannelNotSupported:
		return "logical channel not supported"

	case errSecureMessagingNotSupported:
		return "secure messaging not supported"

	case errCommandChainingNotSupported:
		return "command chaining not supported"

	case errSecurityStatusNotSatisfied:
		return "security status not satisfied"

	case errConditionsOfUseNotSatisfied:
		return "conditions of use not satisfied"

	case errOperationBlocked:
		return "operation blocked"

	case errIncorrectDataParameter:
		return "incorrect data parameter"

	case errFunctionNotSupported:
		return "function not supported"

	case errNotFound:
		return "not found"

	case errNotEnoughMemory:
		return "not enough memory"

	case errIncorrectP1OrP2Parameter:
		return "incorrect p1/p2 param"

	case errKeyReferenceNotFound:
		return "key reference not found"

	case errInstructionNotSupportedOrInvalid:
		return "instruction not supported or invalid"

	case errClassNotSupported:
		return "class not supported"

	case errUnspecifiedCheckingError:
		return "unspecified checking error"

	case errSuccess:
		return "success"
	}

	return fmt.Sprintf("unknown (0x%x%x)", c[0], c[1])
}

// IsMore indicates more data that needs to be fetched
func (c code) IsMore() bool {
	return c[0] == 0x61
}
