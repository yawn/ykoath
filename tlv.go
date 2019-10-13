package ykoath

import (
	"fmt"
)

type tv struct {
	tag   byte
	value []byte
}

type tvs []tv

// read will read a number of tagged values from a buffer
func read(buf []byte) (tvs tvs) {

	var (
		idx    int
		length int
		tag    byte
		value  []byte
	)

	for {

		if len(buf)-idx == 0 {
			return tvs
		}

		// read the tag
		tag = buf[idx]
		idx++

		// read the length
		length = int(buf[idx])
		idx++

		// read the value
		value = buf[idx : idx+length]
		idx = idx + length

		// append the result
		tvs = append(tvs, tv{
			tag:   tag,
			value: value,
		})

	}

}

// Write produces a tlv or lv packet (if the tag is 0)
func write(tag byte, values ...[]byte) []byte {

	var (
		buf    []byte
		length int
		data   []byte
	)

	for _, value := range values {

		// skip nil values (useful for optional tlv segments)
		if value == nil {
			continue
		}

		buf = append(buf, value...)
		length = length + len(value)

	}

	// write the tag unless we skip it (useful for reusing Write for sending the
	// APDU)
	if tag != 0x00 {
		data = append(data, tag)
	}

	// write some length unless this is a one byte value (e.g. for the PUT
	// instruction's "property" byte)
	if length > 1 {
		data = append(data, byte(length))
	}

	if length > 255 {
		panic(fmt.Sprintf("too much data too send (%d bytes)", length))
	}

	return append(data, buf...)

}
