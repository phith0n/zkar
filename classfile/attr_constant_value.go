package classfile

/*
ConstantValue_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 constantvalue_index;
}
*/

type ConstantValueAttribute struct {
	constantValueIndex uint16
}

func (c *ConstantValueAttribute) readInfo(reader *ClassReader) {
	c.constantValueIndex = reader.readUint16()
}

func (c *ConstantValueAttribute) ConstantValueIndex() uint16 {
	return c.constantValueIndex
}
