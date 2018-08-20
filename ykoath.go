package ykoath

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"
	"github.com/yawn/ykoath/tlv"
)

type debugger interface {
	Printf(string, ...interface{})
}

// OATH implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
type OATH struct {
	card    *scard.Card
	context *scard.Context
	Debug   debugger
}

var (
	errUnknownTag = "unknown tag (%x)"
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

	send := append(
		[]byte{cla, ins, p1, p2},
		tlv.Write(0x00, data...)...,
	)

	if o.Debug != nil {
		o.Debug.Printf("SEND % x", send)
	}

	res, err := o.card.Transmit(send)

	if o.Debug != nil {
		o.Debug.Printf("RECV % x", res)
	}

	if err != nil {
		return nil, err
	}

	return tlv.Read(res)

}
