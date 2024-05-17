package classfile

/*
CONSTANT_Integer_info {
    u1 tag;
    u4 bytes;
}
*/

type ConstantIntegerInfo struct {
	val int32
}

func (c *ConstantIntegerInfo) readInfo(reader *ClassReader) {
	bytes := reader.readUint32()
	c.val = int32(bytes)
}

func (c *ConstantIntegerInfo) Value() int32 {
	return c.val
}
