package ykoath

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"
	"github.com/yawn/ykoath/tlv"
)

type OATH struct {
	card    *scard.Card
	context *scard.Context
}

var (
	errNoValuesFound = "no values found in response (% x)"
	errTooMuchData   = "too much data too send (%d bytes)"
	errUnknownTag    = "unknown tag (%x)"
)

func New() (*OATH, error) {

	context, err := scard.EstablishContext()

	if err != nil {
		return nil, err
	}

	readers, err := context.ListReaders()

	if err != nil {
		return nil, err
	}

	for _, reader := range readers {

		if strings.Contains(reader, "Yubikey") {

			card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)

			if err != nil {
				return nil, err
			}

			return &OATH{
				card:    card,
				context: context,
			}, nil

		}

	}

	return nil, fmt.Errorf("no suitable reader found (out of %d readers)", len(readers))

}

func (o *OATH) Close() error {

	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return err
	}

	return o.context.Release()

}

func (o *OATH) send(cla, ins, p1, p2 byte, data ...[]byte) (map[byte][][]byte, error) {

	// TODO: use tlv here and omit nil tags

	var (
		buf    []byte
		length int
	)

	for _, e := range data {
		buf = append(buf, e...)
		length = length + len(e)
	}

	if length > 255 {
		return nil, fmt.Errorf(errTooMuchData, length)
	}

	res, err := o.card.Transmit(append([]byte{
		cla,
		ins,
		p1,
		p2,
		byte(length),
	}, buf...))

	if err != nil {
		return nil, err
	}

	return tlv.Read(res)

}
