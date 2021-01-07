package ykoath

// Constants found in here come from the YKOATH documentation.
// https://developers.yubico.com/OATH/YKOATH_Protocol.html

const (
	// Instructions
	instPut           = 0x01 // Requires auth
	instDelete        = 0x02 // Requires auth
	instSetCode       = 0x03 // Requires auth
	instReset         = 0x04
	instList          = 0xa1 // Requires auth
	instCalculate     = 0xa2 // Requires auth
	instValidate      = 0xa3
	instCalculateAll  = 0xa4 // Requires auth
	instSendRemaining = 0xa5 // Requires auth

	// Response size
	rsFullResponse      = 0x00
	rsTruncatedResponse = 0x01

	// Algorithms
	algoHMACSHA1   = 0x01
	algoHMACSHA256 = 0x02
	algoHMACSHA512 = 0x03

	// OATH Types
	typeHOTP = 0x10
	typeTOTP = 0x20

	// Properties
	propIncreasing   = 0x01
	propRequireTouch = 0x02

	// Tags
	tagBlank             = 0x00
	tagName              = 0x71
	tagNameList          = 0x72
	tagKey               = 0x73
	tagChallenge         = 0x74
	tagResponse          = 0x75
	tagTruncatedResponse = 0x76
	tagNoResponse        = 0x77
	tagProperty          = 0x78
	tagVersion           = 0x79
	tagImf               = 0x7a
	tagAlgorithm         = 0x7b
	tagTouch             = 0x7c

	// Mask
	maskAlgo = 0x0f
	maskType = 0xf0
)

var (
	// Responses
	rsErrWrongSyntax  = []byte{0x6a, 0x80}
	rsErrRequiresAuth = []byte{0x69, 0x82}
	rsErrNoSuchObject = []byte{0x69, 0x84}
	rsErrGenericError = []byte{0x65, 0x81}
)
