package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantMethodType struct {
	DescriptorIndex uint16
}

func (c *ConstantMethodType) ToBytes() []byte {
	var bs = []byte{ConstantMethodTypeInfo}
	bs = append(bs, commons.NumberToBytes(c.DescriptorIndex)...)
	return bs
}

func (cf *ClassFile) readConstantMethodType(stream *commons.Stream) (*ConstantMethodType, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read constant method type failed, no enough data in the stream")
	}

	return &ConstantMethodType{
		DescriptorIndex: binary.BigEndian.Uint16(bs),
	}, nil
}
