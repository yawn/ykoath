package ykoath

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/yawn/ykoath/tlv"
)

func (o *OATH) Calculate(name string) (string, error) {

	var (
		buf       = make([]byte, 8)
		timestamp = time.Now().Unix() / 30
	)

	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	res, err := o.send(0x00, 0xa2, 0x00, 0x01,
		tlv.Write(0x71, []byte(name)),
		tlv.Write(0x74, buf),
	)

	if err != nil {
		return "", err
	}

	for tag, values := range res {

		value := values[0]
		digits := value[0]

		switch tag {
		case 0x76:
			code := binary.BigEndian.Uint32(value[1:])
			return fmt.Sprintf(fmt.Sprintf("%%0%dd", digits), code), nil

		default:
			return "", fmt.Errorf(errUnknownTag, tag)
		}

	}

	return "", fmt.Errorf(errNoValuesFound, res)

}
