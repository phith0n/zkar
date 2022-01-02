package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantNameAndType struct {
	NameIndex       uint16
	DescriptorIndex uint16
}

func (c *ConstantNameAndType) ToBytes() []byte {
	var bs = []byte{CONSTANT_NAME_AND_TYPE_INFO}
	bs = append(bs, commons.NumberToBytes(c.NameIndex)...)
	bs = append(bs, commons.NumberToBytes(c.DescriptorIndex)...)
	return bs
}

func (cf *ClassFile) readConstantNameAndType(stream *commons.Stream) (*ConstantNameAndType, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant name and type failed, no enough data in the stream")
	}

	var c = &ConstantNameAndType{}
	c.NameIndex = binary.BigEndian.Uint16(bs[:2])
	c.DescriptorIndex = binary.BigEndian.Uint16(bs[2:])

	return c, nil
}
