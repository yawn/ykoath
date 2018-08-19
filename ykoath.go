package ykoath

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/ebfe/scard"
	"github.com/yawn/ykoath/tlv"
)

type OATH struct {
	card    *scard.Card
	context *scard.Context
}

type Select struct {
	Algorithm []byte
	Challenge []byte
	Name      []byte
	Version   []byte
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

	for tag, value := range res {

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

func (o *OATH) Close() error {
	o.card.Disconnect(scard.LeaveCard)
	return o.context.Release()
}

func (o *OATH) List() ([]string, error) {

	var names []string

	res, err := o.send(0x00, 0xa1, 0x00, 0x00)

	if err != nil {
		return nil, err
	}

	for tag, value := range res {

		switch tag {
		case 0x72:

			var (
				_    = value[0] // TODO: use type and algorithm
				name = value[1:]
			)

			names = append(names, string(name))

		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	return names, nil

}

func (o *OATH) Select() (*Select, error) {

	var aid = []byte{
		0xa0,
		0x00,
		0x00,
		0x05,
		0x27,
		0x21,
		0x01,
	}

	res, err := o.send(0x00, 0xa4, 0x04, 0x00, aid)

	if err != nil {
		return nil, err
	}

	s := new(Select)

	for tag, value := range res {

		switch tag {
		case 0x7b:
			s.Algorithm = value
		case 0x74:
			s.Challenge = value
		case 0x71:
			s.Name = value
		case 0x79:
			s.Version = value
		default:
			return nil, fmt.Errorf(errUnknownTag, tag)
		}

	}

	return s, nil

}

func (o *OATH) send(cla, ins, p1, p2 byte, data ...[]byte) (map[byte][]byte, error) {

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
