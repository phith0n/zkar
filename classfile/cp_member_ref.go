package classfile

type ConstantMemberRefInfo struct {
	cp               ConstantPool
	classIndex       uint16
	nameAndTypeIndex uint16
}

func (c *ConstantMemberRefInfo) readInfo(reader *ClassReader) {
	c.classIndex = reader.readUint16()
	c.nameAndTypeIndex = reader.readUint16()
}

func (c *ConstantMemberRefInfo) ClassName() string {
	return c.cp.GetClassName(c.classIndex)
}
func (c *ConstantMemberRefInfo) NameAndDescriptor() (string, string) {
	return c.cp.GetNameAndType(c.nameAndTypeIndex)
}
