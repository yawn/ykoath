// SPDX-FileCopyrightText: 2018 Joern Barthel <joern.barthel@kreuzwerker.de>
// SPDX-License-Identifier: Apache-2.0

package ykoath

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	iso "cunicu.li/go-iso7816"
	"cunicu.li/go-iso7816/encoding/tlv"
)

const (
	DefaultTimeStep    = 30 * time.Second
	HMACMinimumKeySize = 14
)

// TLV tags for credential data
const (
	tagName      tlv.Tag = 0x71
	tagNameList  tlv.Tag = 0x72
	tagKey       tlv.Tag = 0x73
	tagChallenge tlv.Tag = 0x74
	tagResponse  tlv.Tag = 0x75
	tagTruncated tlv.Tag = 0x76
	tagHOTP      tlv.Tag = 0x77
	tagProperty  tlv.Tag = 0x78
	tagVersion   tlv.Tag = 0x79
	tagImf       tlv.Tag = 0x7A
	tagAlgorithm tlv.Tag = 0x7B
	tagTouch     tlv.Tag = 0x7C
)

// Instruction bytes for commands
const (
	insList          iso.Instruction = 0xA1
	insSelect        iso.Instruction = 0xA4
	insPut           iso.Instruction = 0x01
	insDelete        iso.Instruction = 0x02
	insSetCode       iso.Instruction = 0x03
	insReset         iso.Instruction = 0x04
	insRename        iso.Instruction = 0x05
	insCalculate     iso.Instruction = 0xA2
	insValidate      iso.Instruction = 0xA3
	insCalculateAll  iso.Instruction = 0xA4
	insSendRemaining iso.Instruction = 0xA5
)

// Card implements most parts of the TOTP portion of the YKOATH specification
// https://developers.yubico.com/Card/YKOATH_Protocol.html
type Card struct {
	*iso.Card

	Clock    func() time.Time
	Timestep time.Duration
	Rand     io.Reader

	tx *iso.Transaction
}

var errUnknownTag = errors.New("unknown tag")

// NewCard initializes a new OATH card.
func NewCard(pcscCard iso.PCSCCard) (*Card, error) {
	isoCard := iso.NewCard(pcscCard)
	isoCard.InsGetRemaining = insSendRemaining

	tx, err := isoCard.NewTransaction()
	if err != nil {
		return nil, fmt.Errorf("failed to initiate transaction: %w", err)
	}

	return &Card{
		Card:     isoCard,
		Clock:    time.Now,
		Timestep: DefaultTimeStep,
		Rand:     rand.Reader,

		tx: tx,
	}, nil
}

// Close terminates an OATH session
func (c *Card) Close() error {
	if c.tx != nil {
		if err := c.tx.EndTransaction(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Card) send(ins iso.Instruction, p1, p2 byte, tvsCmd ...tlv.TagValue) (tvsResp []tlv.TagValue, err error) {
	data, err := tlv.EncodeSimple(tvsCmd...)
	if err != nil {
		return nil, fmt.Errorf("failed to encode command: %w", err)
	}

	res, err := c.Card.Send(&iso.CAPDU{
		Ins:  ins,
		P1:   p1,
		P2:   p2,
		Data: data,
	})
	if err != nil {
		return nil, wrapError(err)
	}

	if tvsResp, err = tlv.DecodeSimple(res); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return tvsResp, nil
}
