package tlv

import (
	"bytes"
	"fmt"
)

// Read will read a number of tagged values from a buffer
func Read(buf []byte) (map[byte][][]byte, error) {

	var (
		idx    int
		length int
		tag    byte
		value  []byte
		values = make(map[byte][][]byte)
	)

	for {

		if len(buf)-idx == 2 {

			var code Error = buf[idx:]

			if bytes.Equal(code, []byte{0x90, 0x00}) {
				return values, nil
			}

			return values, code

		}

		tag = buf[idx]
		idx++

		length = int(buf[idx])
		idx++

		value = buf[idx : idx+length]
		idx = idx + length

		values[tag] = append(values[tag], value)

	}

}

// Write produces a tlv or lv packet (if the tag is 0)
func Write(tag byte, values ...[]byte) []byte {

	var (
		buf    []byte
		length int
		data   []byte
	)

	for _, value := range values {

		if value == nil {
			continue
		}

		buf = append(buf, value...)
		length = length + len(value)

	}

	// write the tag unless we skip it
	if tag != 0x00 {
		data = append(data, tag)
	}

	// write some length unless this is a one byte value
	if length > 1 {
		data = append(data, byte(length))
	}

	if length > 255 {
		panic(fmt.Sprintf("too much data too send (%d bytes)", length))
	}

	return append(data, buf...)

}
