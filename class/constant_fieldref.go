package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantFieldRef struct {
	ClassIndex uint16
	NameAndTypeIndex uint16
}

func (c *ConstantFieldRef) ToBytes() []byte {
	var bs = []byte{CONSTANT_FIELD_REF_INFO}
	bs = append(bs, commons.NumberToBytes(c.ClassIndex)...)
	bs = append(bs, commons.NumberToBytes(c.NameAndTypeIndex)...)
	return bs
}

func (cf *ClassFile) readConstantFieldRef(stream *commons.Stream) (*ConstantFieldRef, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant field ref failed, no enough data in the stream")
	}

	var c = &ConstantFieldRef{}
	c.ClassIndex = binary.BigEndian.Uint16(bs[:2])
	c.NameAndTypeIndex = binary.BigEndian.Uint16(bs[2:])

	return c, nil
}
