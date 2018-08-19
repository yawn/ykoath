package tlv

import "bytes"

// Read will read a number of tagged values from a buffer
func Read(buf []byte) (map[byte][]byte, error) {

	var (
		idx    int
		length int
		tag    byte
		value  []byte
		values = make(map[byte][]byte)
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

		values[tag] = value

	}

}

// Write produces a tlv buf
func Write(tag byte, value []byte) []byte {

	var l = uint8(len(value))

	return append([]byte{
		tag,
		byte(l),
	}, value...)

}
