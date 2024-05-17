package classfile

/*
CONSTANT_MethodType_info {
    u1 tag;
    u2 descriptor_index;
}
*/

type ConstantMethodTypeInfo struct {
	descriptorIndex uint16
}

func (c *ConstantMethodTypeInfo) readInfo(reader *ClassReader) {
	c.descriptorIndex = reader.readUint16()
}
