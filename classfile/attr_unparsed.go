package classfile

/*
attribute_info {
    u2 attribute_name_index;
    u4 attribute_length;
    u1 info[attribute_length];
}
*/

type UnparsedAttribute struct {
	name   string
	length uint32
	info   []byte
}

func (c *UnparsedAttribute) readInfo(reader *ClassReader) {
	c.info = reader.readBytes(c.length)
}

func (c *UnparsedAttribute) Info() []byte {
	return c.info
}
