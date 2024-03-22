package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantInteger struct {
	Integer int32
}

func (c *ConstantInteger) ToBytes() []byte {
	var bs = []byte{ConstantIntegerInfo}
	bs = append(bs, commons.NumberToBytes(c.Integer)...)
	return bs
}

func (cf *ClassFile) readConstantInteger(stream *commons.Stream) (*ConstantInteger, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant integer failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint32(bs)
	var c = &ConstantInteger{
		Integer: int32(i),
	}

	return c, nil
}
