package ykoath

// Delete sends a "DELETE" instruction, removing one named OATH credential
func (o *OATH) Delete(name string) error {

	_, err := o.send(0x00, INST_DELETE, 0x00, 0x00,
		write(TAG_NAME, []byte(name)))

	return err

}
