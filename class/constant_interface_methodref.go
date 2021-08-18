package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantInterfaceMethodRef struct {
	ClassIndex uint16
	NameAndTypeIndex uint16
}

func (c *ConstantInterfaceMethodRef) ToBytes() []byte {
	var bs = []byte{CONSTANT_INTERFACE_METHOD_REF}
	bs = append(bs, commons.NumberToBytes(c.ClassIndex)...)
	bs = append(bs, commons.NumberToBytes(c.NameAndTypeIndex)...)
	return bs
}

func readConstantInterfaceMethodRef(stream *commons.Stream) (*ConstantInterfaceMethodRef, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant interface method ref failed, no enough data in the stream")
	}

	var c = &ConstantInterfaceMethodRef{}
	c.ClassIndex = binary.BigEndian.Uint16(bs[:2])
	c.NameAndTypeIndex = binary.BigEndian.Uint16(bs[2:])

	return c, nil
}
