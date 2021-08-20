package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantModule struct {
	NameIndex uint16
}

func (c *ConstantModule) ToBytes() []byte {
	var bs = []byte{CONSTANT_MODULE_INFO}
	bs = append(bs, commons.NumberToBytes(c.NameIndex)...)
	return bs
}

func (cf *ClassFile) readConstantModule(stream *commons.Stream) (*ConstantModule, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read constant module failed, no enough data in the stream")
	}

	return &ConstantModule{
		NameIndex: binary.BigEndian.Uint16(bs),
	}, nil
}
