package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantClass struct {
	NameIndex uint16
}

func (c *ConstantClass) ToBytes() []byte {
	var bs = []byte{CONSTANT_CLASS_INFO}
	bs = append(bs, commons.NumberToBytes(c.NameIndex)...)
	return bs
}

func readConstantClass(stream *commons.Stream) (*ConstantClass, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(2)
	if err != nil {
		return nil, fmt.Errorf("read constant class failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint16(bs)
	return &ConstantClass{
		NameIndex: i,
	}, nil
}
