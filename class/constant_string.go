package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantString struct {
	StringOffset uint16
	Reference *ConstantUTF8 // Reference must be a ConstantUTF8 object
}

func (c *ConstantString) ToBytes() []byte {
	var bs = []byte{CONSTANT_STRING_INGFO}
	bs = append(bs, commons.NumberToBytes(c.StringOffset)...)
	return bs
}

func readConstantString(stream *commons.Stream) (*ConstantString, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read constant string failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint16(bs)
	return &ConstantString{
		StringOffset: i,
		// lack of Reference because ConstantPool have not been constructed yet
	}, nil
}
