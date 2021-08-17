package class

import (
	"github.com/phith0n/zkar/commons"
)

type ConstantDouble struct {
	Double float64
}

func (c *ConstantDouble) ToBytes() []byte {
	var bs = []byte{CONSTANT_DOUBLE_INFO}
	bs = append(bs, commons.NumberToBytes(c.Double)...)
	return bs
}




