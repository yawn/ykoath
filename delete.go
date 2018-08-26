package ykoath

import (
	"github.com/yawn/ykoath/tlv"
)

// Delete sends a "DELETE" instruction, removing one named OATH credential
func (o *OATH) Delete(name string) error {

	_, err := o.send(0x00, 0x02, 0x00, 0x00,
		tlv.Write(0x71, []byte(name)))

	return err

}
