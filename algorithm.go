package ykoath

import "fmt"

const (
	HmacSha1   Algorithm = 0x01
	HmacSha256 Algorithm = 0x02
	HmacSha512 Algorithm = 0x03
)

type Algorithm byte

func (a Algorithm) String() string {

	switch a {
	case HmacSha1:
		return "HMAC-SHA1"
	case HmacSha256:
		return "HMAC-SHA256"
	case HmacSha512:
		return "HMAC-SHA512"
	default:
		return fmt.Sprintf("unknown %x", byte(a))
	}

}
