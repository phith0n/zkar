package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
	"github.com/phith0n/zkar/serz"
)

type ConstantLong struct {
	Long int64
}

func (c *ConstantLong) ToBytes() []byte {
	var bs = []byte{CONSTANT_LONG_INFO}
	bs = append(bs, serz.NumberToBytes(c.Long)...)
	return bs
}

func readConstantLong(stream *commons.Stream) (*ConstantLong, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(8)
	if err != nil {
		return nil, fmt.Errorf("read constant long failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint64(bs)
	var c = &ConstantLong{
		Long: int64(i),
	}

	return c, nil
}
