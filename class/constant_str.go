package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantString struct {
	StringIndex uint16
}

func (c *ConstantString) ToBytes() []byte {
	var bs = []byte{ConstantStringInfo}
	bs = append(bs, commons.NumberToBytes(c.StringIndex)...)
	return bs
}

func (cf *ClassFile) readConstantString(stream *commons.Stream) (*ConstantString, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read constant string failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint16(bs)
	return &ConstantString{
		StringIndex: i,
	}, nil
}
