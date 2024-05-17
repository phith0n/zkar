package classfile

/*
CONSTANT_String_info {
    u1 tag;
    u2 string_index;
}
*/

type ConstantStringInfo struct {
	cp          ConstantPool
	stringIndex uint16
}

func (c *ConstantStringInfo) readInfo(reader *ClassReader) {
	c.stringIndex = reader.readUint16()
}
func (c *ConstantStringInfo) String() string {
	return c.cp.GetUtf8(c.stringIndex)
}
