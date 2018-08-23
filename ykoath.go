package ykoath

import (
	"fmt"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"github.com/yawn/ykoath/tlv"
)

type card interface {
	Disconnect(scard.Disposition) error
	Transmit([]byte) ([]byte, error)
}

type context interface {
	Release() error
}

type debugger interface {
	Printf(string, ...interface{})
}

// OATH implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
type OATH struct {
	card    card
	clock   func() time.Time
	context context
	Debug   debugger
}

var errUnknownTag = "unknown tag (%x)"

// New initializes a new OATH session
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
				clock:   time.Now,
				context: context,
			}, nil

		}

	}

	return nil, fmt.Errorf("no suitable reader found (out of %d readers)", len(readers))

}

// Close terminates an OATH session
func (o *OATH) Close() error {

	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return err
	}

	return o.context.Release()

}

// send sends an APDU to the card
func (o *OATH) send(cla, ins, p1, p2 byte, data ...[]byte) (map[byte][][]byte, error) {

	var (
		code    code
		results []byte
		send    = append([]byte{cla, ins, p1, p2}, tlv.Write(0x00, data...)...)
	)

	for {

		if o.Debug != nil {
			o.Debug.Printf("SEND % x (%d)", send, len(send))
		}

		res, err := o.card.Transmit(send)

		if err != nil {
			return nil, err
		}

		if o.Debug != nil {
			o.Debug.Printf("RECV % x (%d)", res, len(res))
		}

		code = res[len(res)-2:]
		results = append(results, res[0:len(res)-2]...)

		if code.IsMore() {

			send = []byte{0x00, 0xa5, 0x00, 0x00}

			if o.Debug != nil {
				o.Debug.Printf("MORE %d", int(code[1]))
			}

		} else if code.IsSuccess() {

			if o.Debug != nil {
				o.Debug.Printf("DONE")
			}

			return tlv.Read(results), nil

		} else {
			return nil, code
		}

	}

}
