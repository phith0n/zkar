package classfile

/*
CONSTANT_InvokeDynamic_info {
    u1 tag;
    u2 bootstrap_method_attr_index;
    u2 name_and_type_index;
}
*/

type ConstantInvokeDynamicInfo struct {
	bootstrapMethodAttrIndex uint16
	nameAndTypeIndex         uint16
}

func (c *ConstantInvokeDynamicInfo) readInfo(reader *ClassReader) {
	c.bootstrapMethodAttrIndex = reader.readUint16()
	c.nameAndTypeIndex = reader.readUint16()
}
