// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

const (
	// HmacSha1 describes a HMAC with SHA-1
	HmacSha1 Algorithm = 0x01

	// HmacSha256 describes a HMAC with SHA-2 (256-bit)
	HmacSha256 Algorithm = 0x02

	// HmacSha512 describes a HMAC with SHA-2 (512-bit)
	HmacSha512 Algorithm = 0x03
)

// Algorithm denotes the HMAc algorithm used for deriving the one-time passwords
type Algorithm byte

// String returns a string representation of the algorithm
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

// Hash returns a constructor to create a new hash.Hash object
// for the given algorithm.
func (a Algorithm) Hash() func() hash.Hash {
	switch a {
	case HmacSha1:
		return sha1.New

	case HmacSha256:
		return sha256.New

	case HmacSha512:
		return sha512.New

	default:
		return nil
	}
}
