// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ebfe/scard"
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

var (
	errFailedToConnect            = errors.New("failed to connect to reader")
	errFailedToDisconnect         = errors.New("failed to disconnect from reader")
	errFailedToEstablishContext   = errors.New("failed to establish context")
	errFailedToListReaders        = errors.New("failed to list readers")
	errFailedToListSuitableReader = errors.New("no suitable reader found")
	errFailedToReleaseContext     = errors.New("failed to release context")
	errFailedToTransmit           = errors.New("failed to transmit APDU")
	errUnknownTag                 = errors.New("unknown tag")
)

// New initializes a new OATH session
func New() (*OATH, error) {
	context, err := scard.EstablishContext()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToEstablishContext, err)
	}

	readers, err := context.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errFailedToListReaders, err)
	}

	for _, reader := range readers {
		if strings.Contains(strings.ToLower(reader), "yubikey") {
			card, err := context.Connect(reader, scard.ShareShared, scard.ProtocolAny)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errFailedToConnect, err)
			}

			return &OATH{
				card:    card,
				Clock:   time.Now,
				context: context,
			}, nil
		}
	}

	return nil, fmt.Errorf("%w (out of %d)", errFailedToListSuitableReader, len(readers))
}

// Close terminates an OATH session
func (o *OATH) Close() error {
	if err := o.card.Disconnect(scard.LeaveCard); err != nil {
		return fmt.Errorf("%w: %w", errFailedToDisconnect, err)
	}

	if err := o.context.Release(); err != nil {
		return fmt.Errorf("%w: %w", errFailedToReleaseContext, err)
	}

	return nil
}

// send sends an APDU to the card
// nolint: unparam
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
			return nil, fmt.Errorf("%w: %w", errFailedToTransmit, err)
		}

		if o.Debug != nil {
			o.Debug("RECV % x (%d)", res, len(res))
		}

		code = res[len(res)-2:]
		results = append(results, res[0:len(res)-2]...)

		switch {
		case code.IsMore():
			send = []byte{0x00, 0xa5, 0x00, 0x00}

			if o.Debug != nil {
				o.Debug("MORE %d", int(code[1]))
			}

		case code.IsSuccess():
			if o.Debug != nil {
				o.Debug("DONE")
			}

			return read(results), nil

		default:
			return nil, code
		}
	}
}
