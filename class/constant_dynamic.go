package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantDynamic struct {
	BootstrapMethodIndex uint16 // a reference to the BootstrapMethod in ClassFile.Attributes
	NameAndTypeIndex uint16
}

func (c *ConstantDynamic) ToBytes() []byte {
	var bs = []byte{CONSTANT_DYNAMIC_INFO}
	bs = append(bs, commons.NumberToBytes(c.BootstrapMethodIndex)...)
	bs = append(bs, commons.NumberToBytes(c.NameAndTypeIndex)...)
	return bs
}

func readConstantDynamic(stream *commons.Stream) (*ConstantDynamic, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(4)
	if err != nil {
		return nil, fmt.Errorf("read constant dynamic failed, no enough data in the stream")
	}

	var c = &ConstantDynamic{}
	c.BootstrapMethodIndex = binary.BigEndian.Uint16(bs[:2])
	c.NameAndTypeIndex = binary.BigEndian.Uint16(bs[2:])

	return c, nil
}

