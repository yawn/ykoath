package ykoath

import (
	"fmt"
	"strings"
	"time"

	pcsc "github.com/gballet/go-libpcsclite"
	"github.com/pkg/errors"
)

type card interface {
	Disconnect(uint32) error
	Transmit([]byte) ([]byte, *pcsc.SCardIoRequest, error)
}

type client interface {
	ReleaseContext() error
}

type debugger func(string, ...interface{})

// OATH implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/OATH/YKOATH_Protocol.html
type OATH struct {
	card   card
	Clock  func() time.Time
	client client
	Debug  debugger
}

const (
	errFailedToConnect            = "failed to connect to reader"
	errFailedToDisconnect         = "failed to disconnect from reader"
	errFailedToEstablishContext   = "failed to establish context"
	errFailedToListReaders        = "failed to list readers"
	errFailedToListSuitableReader = "no suitable reader found (out of %d readers)"
	errFailedToReleaseContext     = "failed to release context"
	errFailedToTransmit           = "failed to transmit APDU"
	errUnknownTag                 = "unknown tag (%x)"
)

// New initializes a new OATH session
func New() (*OATH, error) {

	client, err := pcsc.EstablishContext("", pcsc.ScopeSystem)

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToEstablishContext)
	}

	readers, err := client.ListReaders()

	if err != nil {
		return nil, errors.Wrapf(err, errFailedToListReaders)
	}

	for _, reader := range readers {

		if strings.Contains(reader, "Yubikey") {

			card, err := client.Connect(reader, pcsc.ShareShared, pcsc.ProtocolAny)

			if err != nil {
				return nil, errors.Wrapf(err, errFailedToConnect)
			}

			return &OATH{
				card:   card,
				Clock:  time.Now,
				client: client,
			}, nil

		}

	}

	return nil, fmt.Errorf(errFailedToListSuitableReader, len(readers))

}

// Close terminates an OATH session
func (o *OATH) Close() error {

	if err := o.card.Disconnect(pcsc.LeaveCard); err != nil {
		return errors.Wrapf(err, errFailedToDisconnect)
	}

	if err := o.client.ReleaseContext(); err != nil {
		return errors.Wrapf(err, errFailedToReleaseContext)
	}

	return nil

}

// send sends an APDU to the card
func (o *OATH) send(cla, ins, p1, p2 byte, data ...[]byte) (*tvs, error) {

	var (
		code    code
		results []byte
		send    = append([]byte{cla, ins, p1, p2}, write(0x00, data...)...)
	)

	for {

		if o.Debug != nil {
			o.Debug("SEND % x (%d)", send, len(send))
		}

		res, _, err := o.card.Transmit(send)

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
