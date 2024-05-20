package classfile

/*
EnclosingMethod_attribute {
    u2 attribute_name_index;
    u4 attribute_length;
    u2 class_index;
    u2 method_index;
}
*/

type EnclosingMethodAttribute struct {
	cp          ConstantPool
	classIndex  uint16
	methodIndex uint16
}

func (c *EnclosingMethodAttribute) readInfo(reader *ClassReader) {
	c.classIndex = reader.readUint16()
	c.methodIndex = reader.readUint16()
}

func (c *EnclosingMethodAttribute) ClassName() string {
	return c.cp.GetClassName(c.classIndex)
}

func (c *EnclosingMethodAttribute) MethodNameAndDescriptor() (string, string) {
	if c.methodIndex > 0 {
		return c.cp.GetNameAndType(c.methodIndex)
	} else {
		return "", ""
	}
}
