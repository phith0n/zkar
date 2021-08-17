package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

type ConstantInteger struct {
	Integer int32
}

func (c *ConstantInteger) ToBytes() []byte {
	var bs = []byte{CONSTANT_INTEGER_INFO}
	bs = append(bs, serz.NumberToBytes(c.Integer)...)
	return bs
}

func readConstantInteger(stream *commons.Stream) (*ConstantInteger, error) {
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
