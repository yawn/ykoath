package ykoath

import "fmt"

// Algorithm denotes the HMAc algorithm used for deriving the one-time passwords
type Algorithm byte

// String returns a string representation of the algorithm
func (a Algorithm) String() string {

	switch a {
	case algoHMACSHA1:
		return "HMAC-SHA1"
	case algoHMACSHA256:
		return "HMAC-SHA256"
	case algoHMACSHA512:
		return "HMAC-SHA512"
	default:
		return fmt.Sprintf("unknown %x", byte(a))
	}

}
