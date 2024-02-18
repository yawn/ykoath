package ykoath

import (
	"bytes"
	"fmt"
)

// code encapsulates (some) response codes from the spec
type code []byte

// Error return the encapsulated error string
func (c code) Error() string {

	if bytes.Equal(c, rsErrWrongSyntax) {
		return "wrong syntax"
	} else if bytes.Equal(c, rsErrRequiresAuth) {
		return "requires auth"
	} else if bytes.Equal(c, rsErrNoSuchObject) {
		return "no such object"
	} else if bytes.Equal(c, rsErrGenericError) {
		return "generic error"
	}

	return fmt.Sprintf("unknown (% x)", []byte(c))
}

// IsMore indicates more data that needs to be fetched
func (c code) IsMore() bool {
	return len(c) == 2 && c[0] == 0x61
}

// IsSuccess indicates that all data has been successfully fetched
func (c code) IsSuccess() bool {
	return bytes.Equal([]byte{0x90, 00}, c)
}
