package class

import "github.com/phith0n/zkar/serz"

type ConstantDouble struct {
	Double float64
}

func (c *ConstantDouble) ToBytes() []byte {
	var bs = []byte{CONSTANT_DOUBLE_INFO}
	bs = append(bs, serz.NumberToBytes(c.Double)...)
	return bs
}




