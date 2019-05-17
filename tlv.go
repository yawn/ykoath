package ykoath

import (
	"fmt"
)

type tvsTag struct {
	name  byte
	value []byte
}

// tvs is map of tags to slice of byte slices that remembers the insertion order
type tvs struct {
	tags    []byte
	values  map[byte][][]byte
	tagList []tvsTag
}

// add adds another tagged value and memorizes the insertion order
func (t *tvs) add(tag byte, value []byte) {

	prev, ok := t.values[tag]

	if !ok {
		t.tags = append(t.tags, tag)
	}

	t.values[tag] = append(prev, value)

	t.tagList = append(t.tagList, tvsTag{
		name:  tag,
		value: value,
	})
}

// read will read a number of tagged values from a buffer
func read(buf []byte) *tvs {

	var (
		idx    int
		length int
		tag    byte
		tvs    = &tvs{values: make(map[byte][][]byte)}
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
		tvs.add(tag, value)

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
