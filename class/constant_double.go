package class

import (
	"encoding/binary"
	"fmt"
	"github.com/phith0n/zkar/commons"
	"math"
)

type ConstantDouble struct {
	Double float64
}

func (c *ConstantDouble) ToBytes() []byte {
	var bs = []byte{CONSTANT_DOUBLE_INFO}
	bs = append(bs, commons.NumberToBytes(c.Double)...)
	return bs
}

func readConstantDouble(stream *commons.Stream) (*ConstantDouble, error) {
	_, _ = stream.ReadN(1)
	bs, err := stream.ReadN(8)
	if err != nil {
		return nil, fmt.Errorf("read constant double failed, no enough data in the stream")
	}

	var i = binary.BigEndian.Uint64(bs)
	var c = &ConstantDouble{
		Double: math.Float64frombits(i),
	}

	return c, nil
}
