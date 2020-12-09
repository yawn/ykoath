package ykoath

const (
	// Instructions
	INST_PUT            = 0x01 // Requires auth
	INST_DELETE         = 0x02 // Requires auth
	INST_SET_CODE       = 0x03 // Requires auth
	INST_RESET          = 0x04
	INST_LIST           = 0xa1 // Requires auth
	INST_CALCULATE      = 0xa2 // Requires auth
	INST_VALIDATE       = 0xa3
	INST_CALCULATE_ALL  = 0xa4 // Requires auth
	INST_SEND_REMAINING = 0xa5 // Requires auth

	// Response size
	RS_FULL_RESPONSE      = 0x00
	RS_TRUNCATED_RESPONSE = 0x01

	// Algorithms
	A_HMAC_SHA1   = 0x01
	A_HMAC_SHA256 = 0x02
	A_HMAC_SHA512 = 0x03

	// OATH Types
	OT_HOTP = 0x10
	OT_TOTP = 0x20

	// Properties
	PROP_INCREASING    = 0x01
	PROP_REQUIRE_TOUCH = 0x02

	// Tags
	TAG_NAME               = 0x71
	TAG_NAME_LIST          = 0x72
	TAG_KEY                = 0x73
	TAG_CHALLENGE          = 0x74
	TAG_RESPONSE           = 0x75
	TAG_TRUNCATED_RESPONSE = 0x76
	TAG_NO_RESPONSE        = 0x77
	TAG_PROPERTY           = 0x78
	TAG_VERSION            = 0x79
	TAG_IMF                = 0x7a
	TAG_ALGORITHM          = 0x7b
	TAG_TOUCH              = 0x7c

	// Mask
	MASK_ALGO = 0x0f
	MASK_TYPE = 0xf0
)
