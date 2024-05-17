package classfile

import "math"

/*
CONSTANT_Float_info {
    u1 tag;
    u4 bytes;
}
*/

type ConstantFloatInfo struct {
	val float32
}

func (c *ConstantFloatInfo) readInfo(reader *ClassReader) {
	bytes := reader.readUint32()
	c.val = math.Float32frombits(bytes)
}
func (c *ConstantFloatInfo) Value() float32 {
	return c.val
}
