package ykoath

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"github.com/pkg/errors"
)

type card interface {
	Disconnect(scard.Disposition) error
	Transmit([]byte) ([]byte, error)
}

type context interface {
	Release() error
}

type debugger func(string, ...interface{})

// OATH implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
type OATH struct {
	card    card
	Clock   func() time.Time
	context context
	Debug   debugger
}

const (
	errFailedToConnect            = "failed to connect to reader"
	errFailedToDisconnect         = "failed to disconnect from reader"
	errFailedToEstablishContext   = "failed to establish context"
	errFailedToListReaders        = "failed to list readers"
	errFailedToListSuitableReader = "no suitable reader found (out of %d readers)"
	errFailedToReleaseContext     = "failed to release context"
	errFailedToTransmit           = "failed to transmit APDU"
	errFailedToReadSerial         = "failed to read serial"
	errUnknownTag                 = "unknown tag (%x)"
)

// New initializes a new OATH session
func New() (*OATH, error) {
	return NewFromSerial("")
}

// NewFromSerial creates an OATH session for a specific key
func NewFromSerial(serial string) (*OATH, error) {
	context, err := scard.EstablishContext()

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToEstablishContext)
	}

	readers, err := context.ListReaders()

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToListReaders)
	}

	for _, reader := range readers {

		if !strings.Contains(strings.ToLower(reader), "yubikey") {
			continue
		}

		card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToConnect)
		}

		o := OATH{
			card:    card,
			Clock:   time.Now,
			context: context,
		}

		if serial == "" {
			return &o, nil
		}

		cardSerial, err := o.Serial()
		if err != nil {
			return nil, errors.Wrapf(err, errFailedToReadSerial)
		}

		if serial == cardSerial {
			return &o, nil
		}
	}

	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))
}

// Close terminates an OATH session
func (o *OATH) Close() error {

	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return errors.Wrapf(err, errFailedToDisconnect)
	}

	if err := o.context.Release(); err != nil {
		return errors.Wrapf(err, errFailedToReleaseContext)
	}

	return nil

}

func (o *OATH) Serial() (string, error) {
	_, err := o.card.Transmit([]byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17})
	if err != nil {
		return "", err
	}
	resp, err := o.card.Transmit([]byte{0x00, 0x1d, 0x00, 0x00})
	if err != nil {
		return "", err
	}
	kvs := read(resp[1 : len(resp)-2])
	for _, item := range kvs {
		if item.tag == 0x02 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint32(item.value)), 10), nil
		}
	}
	return "", errors.Wrapf(fmt.Errorf("no serial tag found"), errFailedToReleaseContext)
}

// send sends an APDU to the card
func (o *OATH) send(cla, ins, p1, p2 byte, data ...[]byte) (tvs, error) {

	var (
		code    code
		results []byte
		send    = append([]byte{cla, ins, p1, p2}, write(0x00, data...)...)
	)

	for {

		if o.Debug != nil {
			o.Debug("SEND % x (%d)", send, len(send))
		}

		res, err := o.card.Transmit(send)

		if err != nil {
			return nil, errors.Wrapf(err, errFailedToTransmit)
		}

		if o.Debug != nil {
			o.Debug("RECV % x (%d)", res, len(res))
		}

		code = res[len(res)-2:]
		results = append(results, res[0:len(res)-2]...)

		if code.IsMore() {

			send = []byte{0x00, 0xa5, 0x00, 0x00}

			if o.Debug != nil {
				o.Debug("MORE %d", int(code[1]))
			}

		} else if code.IsSuccess() {

			if o.Debug != nil {
				o.Debug("DONE")
			}

			return read(results), nil

		} else {
			return nil, code
		}

	}

}
