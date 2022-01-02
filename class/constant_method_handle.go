package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
)

type ConstantMethodHandle struct {
	ReferenceKind  byte
	ReferenceIndex uint16
}

func (c *ConstantMethodHandle) ToBytes() []byte {
	var bs = []byte{CONSTANT_METHOD_HANDLE_INFO}
	bs = append(bs, c.ReferenceKind)
	bs = append(bs, commons.NumberToBytes(c.ReferenceIndex)...)
	return bs
}

func (cf *ClassFile) readConstantMethodHandle(stream *commons.Stream) (*ConstantMethodHandle, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(3)
	if err != nil {
		return nil, fmt.Errorf("read constant method handle failed, no enough data in the stream")
	}

	return &ConstantMethodHandle{
		ReferenceKind:  bs[0],
		ReferenceIndex: binary.BigEndian.Uint16(bs[1:]),
	}, nil
}
