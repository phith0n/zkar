package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
	"math"
)

type ConstantFloat struct {
	Float float32
}

func (c *ConstantFloat) ToBytes() []byte {
	var bs = []byte{CONSTANT_FLOAT_INFO}
	bs = append(bs, commons.NumberToBytes(c.Float)...)
	return bs
}

func (cf *ClassFile) readConstantFloat(stream *commons.Stream) (*ConstantFloat, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant float failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint32(bs)
	var c = &ConstantFloat{
		Float: math.Float32frombits(i),
	}

	return c, nil
}
